package group.phorus.auth.commons.bdd.steps

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import tools.jackson.databind.json.JsonMapper
import group.phorus.auth.commons.config.AuthMode
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.java.After
import io.cucumber.java.AfterAll
import io.cucumber.java.Before
import io.cucumber.java.BeforeAll
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Jwks
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.*


class IdpAuthStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val securityConfiguration: SecurityConfiguration,
) {

    companion object {
        val wireMockServer = WireMockServer(
            WireMockConfiguration.wireMockConfig()
                .port(18089)
                .jettyAcceptors(1)
                .containerThreads(10)
        )
        private val jsonMapper = JsonMapper()

        // EC key pair for signing (simulates the IdP's signing key)
        private val signingKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        val signingPrivateKey = signingKeyPair.private as ECPrivateKey
        val signingPublicKey = signingKeyPair.public as ECPublicKey

        // A second EC key pair to simulate an "unknown" key
        private val unknownKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        val unknownPrivateKey = unknownKeyPair.private as ECPrivateKey

        // RSA key pair for encryption (simulates our decryption key for nested JWE)
        private val encryptionKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val encryptionPublicKey = encryptionKeyPair.public as RSAPublicKey
        val encryptionPrivateKey = encryptionKeyPair.private as RSAPrivateKey

        private const val ISSUER = "https://test-idp.example.com"
        private const val KID = "test-key-1"

        fun buildJwksJson(): String {
            val jwk = Jwks.builder().key(signingPublicKey).id(KID).build()
            return jsonMapper.writeValueAsString(mapOf("keys" to listOf(jwk)))
        }
    }

    @Before("@idp")
    fun switchToIdpMode() {
        securityConfiguration.mode = AuthMode.IDP_DELEGATED
    }

    @After("@idp")
    fun resetToStandaloneMode() {
        securityConfiguration.mode = AuthMode.STANDALONE
    }

    @Given("the IdP JWKS endpoint serves the signing public key")
    fun `the IdP JWKS endpoint serves the signing public key`() {
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlEqualTo("/.well-known/jwks.json"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody(buildJwksJson())
                )
        )
    }

    @Given("the caller has a valid IdP JWS token with subject {string} and privileges {string}")
    fun `the caller has a valid IdP JWS token`(subject: String, privileges: String) {
        val token = Jwts.builder()
            .header().keyId(KID).and()
            .issuer(ISSUER)
            .subject(subject)
            .claim("scope", privileges)
            .issuedAt(Date.from(Instant.now()))
            .expiration(Date.from(Instant.now().plusSeconds(3600)))
            .signWith(signingPrivateKey)
            .compact()

        baseScenarioScope.objects["idpToken"] = token
    }

    @Given("the caller has a valid IdP nested JWE token with subject {string} and privileges {string}")
    fun `the caller has a valid IdP nested JWE token`(subject: String, privileges: String) {
        // Sign the inner JWS
        val innerJws = Jwts.builder()
            .header().keyId(KID).and()
            .issuer(ISSUER)
            .subject(subject)
            .claim("scope", privileges)
            .issuedAt(Date.from(Instant.now()))
            .expiration(Date.from(Instant.now().plusSeconds(3600)))
            .signWith(signingPrivateKey)
            .compact()

        // Encrypt the JWS as a nested JWE
        val nestedJwe = Jwts.builder()
            .header().contentType("JWT").and()
            .content(innerJws.toByteArray(Charsets.UTF_8))
            .encryptWith(encryptionPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
            .compact()

        baseScenarioScope.objects["idpToken"] = nestedJwe
    }

    @Given("the caller has a valid IdP JWS token with subject {string} and privileges {string} and claim {string} = {string}")
    fun `the caller has a valid IdP JWS token with custom claim`(subject: String, privileges: String, claimName: String, claimValue: String) {
        val token = Jwts.builder()
            .header().keyId(KID).and()
            .issuer(ISSUER)
            .subject(subject)
            .claim("scope", privileges)
            .claim(claimName, claimValue)
            .issuedAt(Date.from(Instant.now()))
            .expiration(Date.from(Instant.now().plusSeconds(3600)))
            .signWith(signingPrivateKey)
            .compact()

        baseScenarioScope.objects["idpToken"] = token
    }

    @Given("the caller has an IdP token signed with an unknown key")
    fun `the caller has an IdP token signed with an unknown key`() {
        val token = Jwts.builder()
            .header().keyId("unknown-kid").and()
            .issuer(ISSUER)
            .subject("550e8400-e29b-41d4-a716-446655440000")
            .claim("scope", "read")
            .issuedAt(Date.from(Instant.now()))
            .expiration(Date.from(Instant.now().plusSeconds(3600)))
            .signWith(unknownPrivateKey)
            .compact()

        baseScenarioScope.objects["idpToken"] = token
    }

    @Then("the response contains userId {string}")
    fun `the response contains userId`(expectedUserId: String) {
        val body = getOrFetchResponseBody()
        assertEquals(expectedUserId, body["userId"])
    }

    @Then("the response contains privilege {string}")
    fun `the response contains privilege`(privilege: String) {
        val body = getOrFetchResponseBody()

        @Suppress("UNCHECKED_CAST")
        val privileges = body["privileges"] as List<String>
        assertTrue(privileges.contains(privilege), "Expected privilege '$privilege' in $privileges")
    }

    private fun getOrFetchResponseBody(): Map<String, Any> {
        @Suppress("UNCHECKED_CAST")
        val cached = baseScenarioScope.objects["idpResponseBody"] as? Map<String, Any>
        if (cached != null) return cached

        val body = responseScenarioScope.responseSpec!!
            .expectBody<Map<String, Any>>().returnResult().responseBody!!
        baseScenarioScope.objects["idpResponseBody"] = body
        return body
    }
}

@BeforeAll
fun setupIdpTests() {
    // Set the encryption private key as system property before Spring context initializes
    System.setProperty(
        "IDP_TEST_ENCRYPTION_PRIVATE_KEY",
        Base64.getEncoder().encodeToString(IdpAuthStepsDefinition.encryptionPrivateKey.encoded)
    )

    IdpAuthStepsDefinition.wireMockServer.start()
}

@AfterAll
fun teardownIdpTests() {
    IdpAuthStepsDefinition.wireMockServer.stop()
    System.clearProperty("IDP_TEST_ENCRYPTION_PRIVATE_KEY")
}
