package group.phorus.auth.commons.services.impl

import com.fasterxml.jackson.databind.ObjectMapper
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import group.phorus.auth.commons.config.*
import group.phorus.auth.commons.services.Validator
import group.phorus.exception.handling.Unauthorized
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Jwks
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.web.reactive.function.client.WebClient
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.*

/**
 * Unit tests for IdP claim extraction logic.
 *
 * Simulates tokens from different IdPs by creating JWS, JWE, and nested JWE tokens
 * with various claim structures and verifying that [IdpAuthenticator] correctly
 * auto-detects the format and extracts the subject and privileges.
 */
class IdpAuthenticatorTest {

    companion object {
        private val mapper = ObjectMapper()
        private lateinit var wireMock: WireMockServer
        private lateinit var webClient: WebClient

        // EC key pair for signing (IdP signs tokens with this)
        private val signingKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        private val privateKey = signingKeyPair.private as ECPrivateKey
        private val publicKey = signingKeyPair.public as ECPublicKey

        // RSA key pair for encryption (IdP encrypts with our public key, we decrypt with private)
        private val encryptionKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        private val encryptionPublicKey = encryptionKeyPair.public as RSAPublicKey
        private val encryptionPrivateKey = encryptionKeyPair.private as RSAPrivateKey

        private const val ISSUER = "https://test-idp.example.com"
        private const val JWKS_PATH = "/.well-known/jwks.json"

        @JvmStatic
        @BeforeAll
        fun startWireMock() {
            wireMock = WireMockServer(
                WireMockConfiguration.wireMockConfig()
                    .dynamicPort()
                    .jettyAcceptors(1)
                    .containerThreads(10)
            )
            wireMock.start()
            webClient = WebClient.builder().build()

            val jwkMap = Jwks.builder().key(publicKey).id("test-key-1").build().toMap()
            val jwksJson = mapper.writeValueAsString(mapOf("keys" to listOf(jwkMap)))

            wireMock.stubFor(
                WireMock.get(WireMock.urlEqualTo(JWKS_PATH))
                    .willReturn(
                        WireMock.aResponse()
                            .withStatus(200)
                            .withHeader(ContentTypeHeader.KEY, "application/json")
                            .withBody(jwksJson)
                    )
            )
        }

        @JvmStatic
        @AfterAll
        fun stopWireMock() {
            wireMock.stop()
        }

        private fun jwksUri() = "http://localhost:${wireMock.port()}$JWKS_PATH"

        /**
         * Creates a JWS token with the given claims, signed with our test EC key pair.
         * The `kid` header is set so [JwksKeyLocator] can resolve the key.
         */
        private fun createIdpToken(claims: Map<String, Any>, kid: String = "test-key-1"): String =
            Jwts.builder()
                .header().keyId(kid).and()
                .claims().add(claims).and()
                .signWith(privateKey)
                .compact()

        /**
         * Creates a JWE token (encrypted only, no signature) with the given claims.
         */
        private fun createIdpJweToken(claims: Map<String, Any>): String =
            Jwts.builder()
                .claims().add(claims).and()
                .encryptWith(encryptionPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
                .compact()

        /**
         * Creates a nested JWE token: signs the claims as a JWS first,
         * then encrypts the JWS as the payload of a JWE with `cty: "JWT"`.
         */
        private fun createIdpNestedJweToken(claims: Map<String, Any>, kid: String = "test-key-1"): String {
            val innerJws = createIdpToken(claims, kid)

            return Jwts.builder()
                .header()
                    .contentType("JWT")
                .and()
                .content(innerJws.toByteArray(Charsets.UTF_8))
                .encryptWith(encryptionPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
                .compact()
        }

        /**
         * Creates a [JwksKeyLocator] backed by WireMock that serves our test public key.
         */
        private fun createKeyLocator(config: SecurityConfiguration): JwksKeyLocator {
            val locator = JwksKeyLocator(config, webClient)
            locator.forceRefresh()
            return locator
        }

        private fun buildConfig(
            subjectClaim: String = "sub",
            privilegesClaim: String = "scope",
        ) = SecurityConfiguration(mode = AuthMode.IDP_DELEGATED).apply {
            idp = IdpConfiguration(
                issuerUri = ISSUER,
                jwkSetUri = jwksUri(),
                claims = IdpClaimsMapping(
                    subject = subjectClaim,
                    privileges = privilegesClaim,
                ),
            )
        }

        private fun buildEncryptedConfig(
            subjectClaim: String = "sub",
            privilegesClaim: String = "scope",
        ) = SecurityConfiguration(mode = AuthMode.IDP_DELEGATED).apply {
            idp = IdpConfiguration(
                issuerUri = ISSUER,
                jwkSetUri = jwksUri(),
                claims = IdpClaimsMapping(
                    subject = subjectClaim,
                    privileges = privilegesClaim,
                ),
                encryption = IdpEncryptionConfiguration(
                    algorithm = "RSA",
                    encodedPrivateKey = Base64.getEncoder().encodeToString(
                        encryptionPrivateKey.encoded
                    ),
                ),
            )
        }
    }

    @Nested
    @DisplayName("Auth0-style tokens")
    inner class Auth0StyleTests {
        @Test
        fun `extracts subject and permissions array`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "permissions")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "auth0|abc123def456",
                "permissions" to listOf("read:users", "write:users", "admin"),
            ))

            val authData = authenticator.authenticate(token)

            // Auth0 subject is not a UUID, so it gets deterministic UUID conversion
            assertNotNull(authData.userId)
            assertEquals(listOf("read:users", "write:users", "admin"), authData.privileges)
        }

        @Test
        fun `extracts space-separated scope string`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scope")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "auth0|abc123",
                "scope" to "openid profile email read:users",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(listOf("openid", "profile", "email", "read:users"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Azure AD / Entra ID-style tokens")
    inner class AzureAdStyleTests {
        @Test
        fun `extracts oid as subject and roles array`() {
            val config = buildConfig(subjectClaim = "oid", privilegesClaim = "roles")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val oid = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "some-pairwise-id",
                "oid" to oid,
                "roles" to listOf("User.ReadWrite", "Application.Admin"),
                "scp" to "access_as_user",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(UUID.fromString(oid), authData.userId)
            assertEquals(listOf("User.ReadWrite", "Application.Admin"), authData.privileges)
        }

        @Test
        fun `extracts scp as space-separated string`() {
            val config = buildConfig(subjectClaim = "oid", privilegesClaim = "scp")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val oid = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "some-pairwise-id",
                "oid" to oid,
                "scp" to "User.Read Mail.Send",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(listOf("User.Read", "Mail.Send"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Keycloak-style tokens (nested claims)")
    inner class KeycloakStyleTests {
        @Test
        fun `extracts roles from nested realm_access path`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "realm_access.roles")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId,
                "realm_access" to mapOf("roles" to listOf("admin", "user", "manager")),
                "preferred_username" to "john.doe",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(UUID.fromString(userId), authData.userId)
            assertEquals(listOf("admin", "user", "manager"), authData.privileges)
        }

        @Test
        fun `returns empty list when nested path does not exist`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "realm_access.roles")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId,
                // No realm_access claim at all
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(emptyList<String>(), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Okta-style tokens")
    inner class OktaStyleTests {
        @Test
        fun `extracts scp array and email subject`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scp")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "john.doe@example.com",
                "scp" to listOf("openid", "profile", "email"),
                "uid" to "00u123abc",
            ))

            val authData = authenticator.authenticate(token)
            // Email subject gets deterministic UUID conversion
            assertNotNull(authData.userId)
            assertEquals(listOf("openid", "profile", "email"), authData.privileges)
        }

        @Test
        fun `extracts groups array`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "groups")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "john.doe@example.com",
                "groups" to listOf("Everyone", "Admins", "Developers"),
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(listOf("Everyone", "Admins", "Developers"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Google / Firebase-style tokens")
    inner class GoogleStyleTests {
        @Test
        fun `extracts standard sub and scope`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scope")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "firebase-uid-12345",
                "scope" to "openid email profile",
            ))

            val authData = authenticator.authenticate(token)
            assertNotNull(authData.userId)
            assertEquals(listOf("openid", "email", "profile"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Edge cases")
    inner class EdgeCaseTests {
        @Test
        fun `missing subject claim throws Unauthorized`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scope")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                // No sub claim
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `expired token throws Unauthorized`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
                "iat" to Date.from(Instant.now().minusSeconds(7200)),
                "exp" to Date.from(Instant.now().minusSeconds(3600)),
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `wrong issuer throws Unauthorized`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to "https://wrong-issuer.example.com",
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `UUID subject is used directly`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val uuid = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to uuid.toString(),
                "scope" to "openid",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(uuid, authData.userId)
        }

        @Test
        fun `non-UUID subject gets deterministic UUID conversion`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val subject = "auth0|abc123def456"
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to subject,
                "scope" to "openid",
            ))

            val authData = authenticator.authenticate(token)
            val expectedUuid = UUID.nameUUIDFromBytes(subject.toByteArray(Charsets.UTF_8))
            assertEquals(expectedUuid, authData.userId)

            // Verify determinism: same subject always gives same UUID
            val authData2 = authenticator.authenticate(token)
            assertEquals(authData.userId, authData2.userId)
        }
    }

    @Nested
    @DisplayName("JWE tokens (encrypted only)")
    inner class JweTokenTests {
        @Test
        fun `decrypts JWE token and extracts claims`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("read", "write"), authData.privileges)
        }

        @Test
        fun `decrypts JWE token with array privileges`() {
            val config = buildEncryptedConfig(privilegesClaim = "permissions")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "permissions" to listOf("admin", "user"),
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("admin", "user"), authData.privileges)
        }

        @Test
        fun `JWE token without encryption config throws Unauthorized`() {
            val config = buildConfig() // no encryption config
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `JWE token with wrong issuer throws Unauthorized`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpJweToken(mapOf(
                "iss" to "https://wrong-issuer.example.com",
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }
    }

    @Nested
    @DisplayName("Nested JWE tokens (sign then encrypt)")
    inner class NestedJweTokenTests {
        @Test
        fun `decrypts and verifies nested JWE token`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write admin",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("read", "write", "admin"), authData.privileges)
        }

        @Test
        fun `decrypts nested JWE with custom claim mapping`() {
            val config = buildEncryptedConfig(subjectClaim = "oid", privilegesClaim = "roles")
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to "pairwise-id",
                "oid" to userId.toString(),
                "roles" to listOf("User.ReadWrite", "Admin"),
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("User.ReadWrite", "Admin"), authData.privileges)
        }

        @Test
        fun `nested JWE without encryption config throws Unauthorized`() {
            val config = buildConfig() // no encryption config
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `nested JWE with wrong issuer throws Unauthorized`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpNestedJweToken(mapOf(
                "iss" to "https://wrong-issuer.example.com",
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `non-UUID subject in nested JWE gets deterministic UUID`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val subject = "signicat|user-12345"
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to subject,
                "scope" to "openid profile",
            ))

            val authData = authenticator.authenticate(token)
            val expectedUuid = UUID.nameUUIDFromBytes(subject.toByteArray(Charsets.UTF_8))
            assertEquals(expectedUuid, authData.userId)
            assertEquals(listOf("openid", "profile"), authData.privileges)
        }

        @Test
        fun `properties include all standard JWT claims for validator access`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "aud" to "test-audience",
                "scope" to "read write",
                "custom_claim" to "custom_value",
            ))

            val authData = authenticator.authenticate(token)

            // Standard claims should be accessible to validators
            assertNotNull(authData.properties[Claims.ISSUER])
            assertEquals(ISSUER, authData.properties[Claims.ISSUER])
            assertNotNull(authData.properties[Claims.SUBJECT])
            assertEquals(userId.toString(), authData.properties[Claims.SUBJECT])
            assertNotNull(authData.properties[Claims.AUDIENCE])
            // aud is stored as list by JJWT, toString() converts it to [value] format
            assertEquals("[test-audience]", authData.properties[Claims.AUDIENCE])
            assertNotNull(authData.properties["scope"])
            assertEquals("read write", authData.properties["scope"])
            
            // Custom claims should also be present
            assertEquals("custom_value", authData.properties["custom_claim"])
        }
    }

    @Nested
    @DisplayName("Low-level parse methods")
    inner class ParseMethodTests {
        @Test
        fun `parseSignedClaims returns raw Jws object for JWS token`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            val jws = authenticator.parseSignedClaims(token)
            assertEquals(userId.toString(), jws.payload.subject)
            assertEquals(ISSUER, jws.payload.issuer)
            assertEquals("read write", jws.payload["scope"])
        }

        @Test
        fun `parseEncryptedClaims returns raw Jwe object for JWE token`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "admin",
            ))

            val jwe = authenticator.parseEncryptedClaims(token)
            assertEquals(userId.toString(), jwe.payload.subject)
            assertEquals(ISSUER, jwe.payload.issuer)
            assertEquals("admin", jwe.payload["scope"])
        }

        @Test
        fun `parseSignedClaims throws Unauthorized for invalid token`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            assertThrows<Unauthorized> {
                authenticator.parseSignedClaims("invalid.token.here")
            }
        }

        @Test
        fun `parseEncryptedClaims throws Unauthorized without encryption config`() {
            val config = buildConfig() // no encryption config
            val locator = createKeyLocator(config)
            val authenticator = IdpAuthenticator(config, locator)

            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> {
                authenticator.parseEncryptedClaims(token)
            }
        }
    }

    @Nested
    @DisplayName("enableValidators flag")
    inner class EnableValidatorsTests {
        @Test
        fun `enableValidators false skips validator execution`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(rejectingValidator))

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            // Should succeed because validators are disabled
            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(userId, authData.userId)
        }

        @Test
        fun `enableValidators true invokes validators (default)`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(rejectingValidator))

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "read write",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }
    }

    @Nested
    @DisplayName("Validator integration")
    inner class ValidatorTests {
        @Test
        fun `validators are invoked and can reject tokens`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(rejectingValidator))

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "read write",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `accepting validators do not reject tokens`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val acceptingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = true
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(acceptingValidator))

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read",
            ))

            val authData = authenticator.authenticate(token)
            assertEquals(userId, authData.userId)
        }

        @Test
        fun `multiple validators are all invoked`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val acceptingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = true
            }
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "custom_claim"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(acceptingValidator, rejectingValidator))

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "read",
                "custom_claim" to "bad_value",
            ))

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `validator receives all properties for cross-claim validation`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            var receivedProperties: Map<String, String> = emptyMap()
            val capturingValidator = object : Validator {
                override fun accepts(property: String) = property == "custom_claim"
                override fun isValid(value: String, properties: Map<String, String>): Boolean {
                    receivedProperties = properties
                    return true
                }
            }
            val authenticator = IdpAuthenticator(config, locator, listOf(capturingValidator))

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
                "custom_claim" to "test_value",
            ))

            authenticator.authenticate(token)

            // Validator should have received all claims including standard ones
            assertNotNull(receivedProperties[Claims.ISSUER])
            assertNotNull(receivedProperties[Claims.SUBJECT])
            assertNotNull(receivedProperties["scope"])
            assertEquals("test_value", receivedProperties["custom_claim"])
        }
    }
}
