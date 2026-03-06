package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.dtos.AuthData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.Validator
import group.phorus.exception.handling.Unauthorized
import io.jsonwebtoken.*
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.stereotype.Service
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

/**
 * [Authenticator] implementation that validates tokens issued by an external Identity Provider (IdP).
 *
 * ### Supported token formats
 * The token format is auto-detected at parse time:
 *
 * | Format | Detection | Validation |
 * |--------|-----------|------------|
 * | **JWS** | 3 Base64url segments | Signature verification via JWKS. |
 * | **JWE** | 5 segments, no `cty: "JWT"` | Decryption using the configured `idp.encryption` private key. |
 * | **Nested JWE** | 5 segments, `cty: "JWT"` | Decryption, then inner JWS signature verification via JWKS. |
 *
 * JWE and nested JWE require `idp.encryption.encoded-private-key` to be configured.
 *
 * ### Validation flow
 * 1. Detect format by counting `.` separators.
 * 2. For JWE tokens, peek at the unencrypted JOSE header for `cty: "JWT"` to detect nesting.
 * 3. Parse / decrypt / verify as appropriate.
 * 4. Validate the `iss` (issuer) claim against the configured
 *    [issuerUri][group.phorus.auth.commons.config.IdpConfiguration.issuerUri].
 * 5. Map claims to [AuthData] using the configurable
 *    [IdpClaimsMapping][group.phorus.auth.commons.config.IdpClaimsMapping].
 * 6. Run registered [Validator] beans (optional).
 * 7. Return [AuthData].
 *
 * ### Claim extraction
 * - **Subject**: read from the claim named by `idp.claims.subject` (default `sub`).
 * - **Privileges**: read from the claim named by `idp.claims.privileges` (default `scope`).
 *   Supports three value formats transparently:
 *   - Space-separated string (e.g. Auth0 `scope`, Azure AD `scp`)
 *   - JSON array of strings (e.g. Auth0 `permissions`, Okta `scp`, Azure AD `roles`)
 *   - Nested JSON path with dot notation (e.g. Keycloak `realm_access.roles`)
 *
 * ### IdP compatibility
 * | IdP | Subject config | Privileges config |
 * |-----|---------------|------------------|
 * | Auth0 | `sub` (default) | `permissions` or `scope` |
 * | Azure AD / Entra ID | `oid` | `scp` or `roles` |
 * | Google / Firebase | `sub` (default) | `scope` or custom |
 * | Keycloak | `sub` (default) | `realm_access.roles` |
 * | Okta | `sub` (default) | `scp` or `groups` |
 *
 * @see JwksKeyLocator
 * @see group.phorus.auth.commons.config.IdpConfiguration
 * @see group.phorus.auth.commons.config.IdpClaimsMapping
 * @see Validator
 */
@AutoConfiguration(after = [JwksKeyLocator::class])
@Service
@Qualifier("idp")
@ConditionalOnBean(JwksKeyLocator::class)
class IdpAuthenticator(
    private val securityConfiguration: SecurityConfiguration,
    private val jwksKeyLocator: JwksKeyLocator,
    private val validators: List<Validator> = emptyList(),
) : Authenticator {

    private val log = LoggerFactory.getLogger(IdpAuthenticator::class.java)

    override fun authenticate(jwt: String, enableValidators: Boolean): AuthData {
        val enabledValidators = if (enableValidators) validators else emptyList()
        val claims = parseToken(jwt)

        val claimsMapping = securityConfiguration.idp.claims

        // Extract subject (user ID)
        val subject = extractStringClaim(claims, claimsMapping.subject)
            ?: throw Unauthorized("IdP token is missing the '${claimsMapping.subject}' claim")

        val userId = runCatching { UUID.fromString(subject) }.getOrElse {
            // Many IdPs use non-UUID subject identifiers (e.g. Auth0 "auth0|abc123",
            // Okta email addresses). Generate a deterministic UUID from the string.
            UUID.nameUUIDFromBytes(subject.toByteArray(Charsets.UTF_8))
        }

        // Extract privileges (scopes / roles)
        val privileges = extractPrivileges(claims, claimsMapping.privileges)

        // Extract JTI if present
        val jti = claims.id ?: UUID.nameUUIDFromBytes(
            "$subject-${claims.issuedAt?.time ?: System.currentTimeMillis()}"
                .toByteArray(Charsets.UTF_8)
        ).toString()

        // Collect all claims as properties and run validators
        val properties = claims.mapNotNull { (key, value) ->
            key to value.toString()
        }.toMap().also { props ->
            props.forEach { (key, value) ->
                enabledValidators.filter { it.accepts(key) }.forEach { validator ->
                    if (!validator.isValid(value, props))
                        throw Unauthorized("IdP token validation failed")
                }
            }
        }

        return AuthData(
            userId = userId,
            tokenType = TokenType.ACCESS_TOKEN,
            jti = jti,
            privileges = privileges,
            properties = properties,
        )
    }

    override fun parseSignedClaims(jwt: String): Jws<Claims> = verifyJws(jwt)

    override fun parseEncryptedClaims(jwt: String): Jwe<Claims> = decryptJweClaims(jwt)

    /**
     * Auto-detects the IdP token format and extracts claims accordingly.
     *
     * - 3 segments -> JWS (signature verification via JWKS)
     * - 5 segments -> JWE or nested JWE (decryption required)
     */
    private fun parseToken(jwt: String): Claims {
        val segmentCount = jwt.count { it == '.' } + 1

        return when (segmentCount) {
            3 -> verifyJws(jwt).payload
            5 -> {
                val isNested = peekJweContentType(jwt).equals("JWT", ignoreCase = true)
                if (isNested) parseNestedJwe(jwt) else decryptJweClaims(jwt).payload
            }
            else -> throw Unauthorized("Invalid IdP Token")
        }
    }

    private fun verifyJws(jwt: String): Jws<Claims> =
        runCatching {
            val parserBuilder = Jwts.parser()
                .keyLocator(jwksKeyLocator)

            securityConfiguration.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseSignedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    private fun decryptJweClaims(jwt: String): Jwe<Claims> =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()

            val parserBuilder = Jwts.parser()
                .decryptWith(privateKey)

            securityConfiguration.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseEncryptedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    /**
     * Parses a nested JWE: decrypts the outer JWE to obtain the inner JWS compact string,
     * then verifies the inner JWS signature and extracts claims.
     */
    private fun parseNestedJwe(jwt: String): Claims =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()

            // Decrypt the outer JWE to get the inner JWS string
            val jwe = Jwts.parser()
                .decryptWith(privateKey)
                .build()
                .parseEncryptedContent(jwt)

            val innerJwsString = jwe.payload.toString(Charsets.UTF_8)

            // Verify the inner JWS signature using JWKS
            val parserBuilder = Jwts.parser()
                .keyLocator(jwksKeyLocator)

            securityConfiguration.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseSignedClaims(innerJwsString).payload
        }.getOrElse { handleParsingException(it) }

    /**
     * Peeks at the first Base64url segment of a JWE to extract the `cty` (Content Type)
     * header without performing decryption. A value of `"JWT"` indicates a nested JWT.
     */
    private fun peekJweContentType(jwt: String): String? =
        runCatching {
            val headerSegment = jwt.substringBefore('.')
            val headerJson = Base64.getUrlDecoder().decode(headerSegment).toString(Charsets.UTF_8)
            val ctyRegex = """"cty"\s*:\s*"([^"]+)"""".toRegex()
            ctyRegex.find(headerJson)?.groupValues?.get(1)
        }.getOrNull()

    private fun resolveEncryptionPrivateKey(): PrivateKey {
        val enc = securityConfiguration.idp.encryption
        val encodedKey = enc.encodedPrivateKey
            ?: throw Unauthorized("IdP encryption private key is not configured but an encrypted IdP token was received")
        val keyBytes = Base64.getDecoder().decode(encodedKey)
        val keyFactory = KeyFactory.getInstance(enc.algorithm)
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    private fun <T> handleParsingException(it: Throwable): T {
        when (it) {
            is SecurityException,
            is IllegalArgumentException,
            is MalformedJwtException,
            is UnsupportedJwtException -> throw Unauthorized("Invalid IdP Token")
            is ExpiredJwtException -> throw Unauthorized("IdP Token expired")
            is IncorrectClaimException -> {
                log.warn("IdP token claim validation failed: {}", it.message)
                throw Unauthorized("IdP Token validation failed: ${it.claimName}")
            }
            is MissingClaimException -> {
                log.warn("IdP token missing required claim: {}", it.claimName)
                throw Unauthorized("IdP Token missing required claim: ${it.claimName}")
            }
            else -> throw Unauthorized("Unknown exception validating IdP Token: ${it.message}")
        }
    }

    /**
     * Extracts a string claim from the claims set.
     */
    private fun extractStringClaim(claims: Claims, claimName: String): String? {
        val value = resolveClaim(claims, claimName) ?: return null
        return value.toString()
    }

    /**
     * Extracts privileges from the claims set.
     *
     * Handles three formats transparently:
     * - **Space-separated string**: `"read write admin"` -> `["read", "write", "admin"]`
     * - **JSON array**: `["read", "write", "admin"]` -> `["read", "write", "admin"]`
     * - **Nested path**: `realm_access.roles` resolves `{"realm_access": {"roles": ["admin"]}}` -> `["admin"]`
     */
    private fun extractPrivileges(claims: Claims, claimName: String): List<String> {
        val value = resolveClaim(claims, claimName) ?: return emptyList()

        return when (value) {
            is String -> value.split(" ").filter { it.isNotBlank() }
            is Collection<*> -> value.mapNotNull { it?.toString() }
            else -> listOf(value.toString())
        }
    }

    /**
     * Resolves a claim value, supporting dot-notation for nested paths.
     *
     * For example, `realm_access.roles` navigates into:
     * ```json
     * { "realm_access": { "roles": ["admin", "user"] } }
     * ```
     * and returns the `["admin", "user"]` array.
     *
     * This enables compatibility with Keycloak and other IdPs that use nested claim structures.
     */
    @Suppress("UNCHECKED_CAST")
    private fun resolveClaim(claims: Claims, path: String): Any? {
        if ('.' !in path) {
            return claims[path]
        }

        val parts = path.split('.')
        var current: Any? = claims

        for (part in parts) {
            current = when (current) {
                is Map<*, *> -> current[part]
                else -> return null
            }
        }

        return current
    }
}
