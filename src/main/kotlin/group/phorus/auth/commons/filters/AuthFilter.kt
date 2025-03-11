package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.dtos.AuthContextData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.exception.handling.Unauthorized
import group.phorus.mapper.mapping.extensions.mapTo
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.withContext
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpHeaders.AUTHORIZATION
import org.springframework.http.HttpMethod
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange
import kotlin.coroutines.coroutineContext


@AutoConfiguration
@ConditionalOnProperty(prefix = "group.phorus.security", name = ["enableFilter"], havingValue = "true", matchIfMissing = true)
class AuthFilter(
    private val securityConfiguration: SecurityConfiguration,
    private val authenticator: Authenticator,
) : CoWebFilter() {
    private val headerPrefix = "Bearer "

    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        val path = exchange.request.path.value()
        val method = exchange.request.method

        val isIgnoredPath = securityConfiguration.ignoredPaths.any {
            path.contains(it.path) && (it.method == null || HttpMethod.valueOf(it.method!!) == method)
        }
        if (isIgnoredPath) {
            return withContext(coroutineContext) {
                chain.filter(exchange)
            }
        }

        val header = exchange.request.headers.getFirst(AUTHORIZATION)
            ?: throw Unauthorized("Authorization header is missing or invalid")

        if (header.length <= headerPrefix.length) throw Unauthorized("Invalid authorization header size")
        if (!header.contains(headerPrefix)) throw Unauthorized("Bearer token not found")

        val jwt = header.substring(headerPrefix.length)

        val authData = authenticator.authenticate(jwt)

        if (authData.tokenType == TokenType.REFRESH_TOKEN && securityConfiguration.refreshTokenPath == null)
            throw Unauthorized("Invalid access token")

        if (authData.tokenType == TokenType.REFRESH_TOKEN
            && securityConfiguration.refreshTokenPath != null
            && !path.contains(securityConfiguration.refreshTokenPath!!))
            throw Unauthorized("Invalid access token")

        val authContextData = authData.mapTo<AuthContextData>()!!

        return withContext(coroutineContext + AuthContext.context.asContextElement(value = authContextData)) {
            chain.filter(exchange)
        }
    }
}
