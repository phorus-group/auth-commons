package group.phorus.auth.commons.services

import group.phorus.auth.commons.dtos.AuthData
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwe
import io.jsonwebtoken.Jws

/**
 * Validates a compact-serialized JWT and extracts authentication data.
 *
 * Two implementations are provided, selected by the configured
 * [authentication mode][group.phorus.auth.commons.config.AuthMode]:
 *
 * | Mode | Implementation | Key source |
 * |------|---------------|------------|
 * | **STANDALONE** | [StandaloneAuthenticator][group.phorus.auth.commons.services.impl.StandaloneAuthenticator] (primary) | Locally configured signing / encryption keys. |
 * | **IDP_BRIDGE** | [StandaloneAuthenticator][group.phorus.auth.commons.services.impl.StandaloneAuthenticator] (primary) for own tokens, [IdpAuthenticator][group.phorus.auth.commons.services.impl.IdpAuthenticator] for IdP tokens. | Local keys + remote JWKS. |
 * | **IDP_DELEGATED** | [IdpAuthenticator][group.phorus.auth.commons.services.impl.IdpAuthenticator] | Remote JWKS endpoint + optional IdP encryption keys. |
 *
 * Both implementations auto-detect the token format (JWS / JWE / nested-JWE) at parse time
 * and run registered [Validator] beans after claim extraction.
 */
interface Authenticator {
    /**
     * Authenticates a compact-serialized JWT string and returns the extracted [AuthData].
     *
     * The token format (JWS / JWE / nested-JWE) is **auto-detected** based on the number of
     * Base64url segments (3 = JWS, 5 = JWE or nested-JWE).
     *
     * @param jwt              The compact-serialized token (without the `Bearer ` prefix).
     * @param enableValidators When `true` (default), registered [Validator] beans are invoked
     *                         after claim extraction. Set to `false` to skip custom validation
     *                         (e.g. when converting a token via [group.phorus.auth.commons.config.UserContextConverter]).
     * @return Parsed [AuthData] containing user ID, token type, JTI, privileges, and custom properties.
     * @throws group.phorus.exception.handling.Unauthorized on any validation failure.
     */
    fun authenticate(jwt: String, enableValidators: Boolean = true): AuthData

    /**
     * Low-level: parses a JWE token and returns the raw JJWT [Jwe] object.
     *
     * Only applicable when the token format includes encryption (JWE or nested-JWE).
     *
     * @param jwt The compact-serialized JWE token.
     * @return The decrypted [Jwe] containing [Claims].
     * @throws group.phorus.exception.handling.Unauthorized on any parsing or decryption failure.
     */
    fun parseEncryptedClaims(jwt: String): Jwe<Claims>

    /**
     * Low-level: parses a JWS token and returns the raw JJWT [Jws] object.
     *
     * Only applicable when the token format is JWS.
     *
     * @param jwt The compact-serialized JWS token.
     * @return The verified [Jws] containing [Claims].
     * @throws group.phorus.exception.handling.Unauthorized on any parsing or signature verification failure.
     */
    fun parseSignedClaims(jwt: String): Jws<Claims>
}
