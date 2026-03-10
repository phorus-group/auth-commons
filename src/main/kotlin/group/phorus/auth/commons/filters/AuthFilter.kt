package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.AuthMode
import group.phorus.auth.commons.config.MetricsRecorder
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
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpHeaders.AUTHORIZATION
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
 * Two mutually exclusive modes control which paths require token authentication:
 * - **[group.phorus.auth.commons.config.TokenFilterConfiguration.ignoredPaths]**: all paths
 *   are filtered **except** the listed ones.
 * - **[group.phorus.auth.commons.config.TokenFilterConfiguration.protectedPaths]**: **only**
 *   the listed paths are filtered; everything else is skipped.
 *
 * If both are configured, the filter throws an [IllegalStateException].
 *
 * Additionally, refresh tokens are only accepted on the configured
 * [group.phorus.auth.commons.config.TokenFilterConfiguration.refreshTokenPath];
 * all other paths reject them with a 401.
 *
 * ### Filter ordering
 * This filter runs **after** [ApiKeyFilter] so that API key validation can fail fast
 * before requiring any JWT parsing.
 *
 * ### Enabling / disabling
 * Controlled by `group.phorus.security.filters.token.enabled` (default: `false`).
 *
 * @see AuthContext
 * @see Authenticator
 * @see group.phorus.auth.commons.config.TokenFilterConfiguration
 */
@AutoConfiguration
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
class AuthFilter(
    private val securityConfiguration: SecurityConfiguration,
    private val authenticator: Authenticator,
    idpAuthenticatorProvider: ObjectProvider<IdpAuthenticator>,
    metricsProvider: ObjectProvider<MetricsRecorder>,
) : CoWebFilter() {
    private val headerPrefix = "Bearer "
    private val idpAuthenticator = idpAuthenticatorProvider.getIfAvailable()
    private val metrics = metricsProvider.getIfAvailable()

    init {
        val config = securityConfiguration.filters.token
        require(config.ignoredPaths.isEmpty() || config.protectedPaths.isEmpty()) {
            "Token filter cannot have both ignored-paths and protected-paths configured. " +
            "Use ignored-paths to skip specific paths, or protected-paths to only filter specific paths."
        }
    }

    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        val tokenConfig = securityConfiguration.filters.token
        if (!tokenConfig.enabled) return chain.filter(exchange)

        val path = exchange.request.path.value()
        val method = exchange.request.method

        if (shouldSkipPath(tokenConfig.ignoredPaths, tokenConfig.protectedPaths, path, method)) {
            return chain.filter(exchange)
        }

        val header = exchange.request.headers.getFirst(AUTHORIZATION)
            ?: throw Unauthorized("Authorization header is missing or invalid")

        if (header.length <= headerPrefix.length) throw Unauthorized("Invalid authorization header size")
        if (!header.contains(headerPrefix)) throw Unauthorized("Bearer token not found")

        val jwt = header.substring(headerPrefix.length)
        val mode = securityConfiguration.mode.name.lowercase()

        suspend fun performAuthentication() = when (securityConfiguration.mode) {
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

        val authData = metrics?.timeAuthentication(mode) { performAuthentication() }
            ?: performAuthentication()

        if (authData.tokenType == TokenType.REFRESH_TOKEN && tokenConfig.refreshTokenPath == null)
            throw Unauthorized("Invalid access token")

        if (authData.tokenType == TokenType.REFRESH_TOKEN
            && tokenConfig.refreshTokenPath != null
            && !path.contains(tokenConfig.refreshTokenPath!!))
            throw Unauthorized("Invalid access token")

        val authContextData = authData.mapTo<AuthContextData>()!!

        return withContext(AuthContext.context.asContextElement(value = authContextData)) {
            chain.filter(exchange)
        }
    }
}
