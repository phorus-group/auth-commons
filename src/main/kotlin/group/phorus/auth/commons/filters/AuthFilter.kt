package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.AuthMode
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.dtos.AuthContextData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.impl.IdpAuthenticator
import group.phorus.exception.handling.Unauthorized
import group.phorus.mapper.mapping.extensions.mapTo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.withContext
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpHeaders.AUTHORIZATION
import org.springframework.http.HttpMethod
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange

/**
 * WebFilter that extracts the `Authorization: Bearer <token>` header, validates the token,
 * and populates the [AuthContext] coroutine context element with the authenticated user's data.
 *
 * ### Behavior by authentication mode
 *
 * | Mode | Token source | Validator used |
 * |------|-------------|----------------|
 * | [AuthMode.STANDALONE] | Own tokens (JWS / JWE / nested-JWE) | [Authenticator] (primary) |
 * | [AuthMode.IDP_BRIDGE] | Own tokens (created after IdP bridge) | [Authenticator] (primary) |
 * | [AuthMode.IDP_DELEGATED] | IdP-issued tokens (JWS / JWE / nested-JWE) | [IdpAuthenticator] |
 *
 * ### Path filtering
 * - Paths listed in [SecurityConfiguration.ignoredPaths] bypass authentication entirely.
 * - Refresh tokens are only accepted on the [SecurityConfiguration.refreshTokenPath],
 *   all other paths are rejected with a 401.
 *
 * The filter is disabled when `group.phorus.security.enable-filter` is explicitly set to `false`.
 *
 * @see AuthContext
 * @see Authenticator
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "group.phorus.security", name = ["enableFilter", "enable-filter"], havingValue = "true", matchIfMissing = true)
class AuthFilter(
    private val securityConfiguration: SecurityConfiguration,
    private val authenticator: Authenticator,
    private val idpAuthenticator: IdpAuthenticator?,
) : CoWebFilter() {
    private val headerPrefix = "Bearer "

    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        val path = exchange.request.path.value()
        val method = exchange.request.method

        val isIgnoredPath = securityConfiguration.ignoredPaths.any {
            path.startsWith(it.path) && (it.method == null || HttpMethod.valueOf(it.method!!) == method)
        }
        if (isIgnoredPath) {
            return chain.filter(exchange)
        }

        val header = exchange.request.headers.getFirst(AUTHORIZATION)
            ?: throw Unauthorized("Authorization header is missing or invalid")

        if (header.length <= headerPrefix.length) throw Unauthorized("Invalid authorization header size")
        if (!header.contains(headerPrefix)) throw Unauthorized("Bearer token not found")

        val jwt = header.substring(headerPrefix.length)

        val authData = when (securityConfiguration.mode) {
            AuthMode.STANDALONE, AuthMode.IDP_BRIDGE -> {
                authenticator.authenticate(jwt)
            }
            AuthMode.IDP_DELEGATED -> {
                val idpAuth = idpAuthenticator
                    ?: throw IllegalStateException(
                        "IdpAuthenticator is not configured. Set group.phorus.security.idp.jwk-set-uri " +
                        "for IDP_DELEGATED mode."
                    )
                withContext(Dispatchers.IO) { idpAuth.authenticate(jwt) }
            }
        }

        if (authData.tokenType == TokenType.REFRESH_TOKEN && securityConfiguration.refreshTokenPath == null)
            throw Unauthorized("Invalid access token")

        if (authData.tokenType == TokenType.REFRESH_TOKEN
            && securityConfiguration.refreshTokenPath != null
            && !path.contains(securityConfiguration.refreshTokenPath!!))
            throw Unauthorized("Invalid access token")

        val authContextData = authData.mapTo<AuthContextData>()!!

        return withContext(AuthContext.context.asContextElement(value = authContextData)) {
            chain.filter(exchange)
        }
    }
}
