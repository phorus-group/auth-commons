package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.MetricsRecorder
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.context.ApiKeyContext
import group.phorus.auth.commons.dtos.ApiKeyContextData
import group.phorus.auth.commons.services.ApiKeyValidator
import group.phorus.exception.handling.Unauthorized
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange
import java.security.MessageDigest

/**
 * WebFilter that extracts an API key from a configurable HTTP header, validates it,
 * and populates the [ApiKeyContext] coroutine context element with the resolved identity.
 *
 * ### Validation order
 *
 * 1. **Static keys**: if [group.phorus.auth.commons.config.ApiKeyFilterConfiguration.keys] is non-empty,
 *    the header value is compared against the configured values. On match, the map key becomes the key id.
 * 2. **Custom validator**: if an [ApiKeyValidator] bean exists, it is called. On a valid result, its
 *    [group.phorus.auth.commons.services.ApiKeyValidationResult.keyId] and metadata are used.
 * 3. If neither matches, a 401 is returned. If neither is configured, an [IllegalStateException] is thrown.
 *
 * ### Path filtering
 * Two mutually exclusive modes control which paths require API key authentication:
 * - **[group.phorus.auth.commons.config.ApiKeyFilterConfiguration.ignoredPaths]**: all paths
 *   are filtered **except** the listed ones.
 * - **[group.phorus.auth.commons.config.ApiKeyFilterConfiguration.protectedPaths]**: **only**
 *   the listed paths are filtered; everything else is skipped.
 *
 * If both are configured, the filter throws an [IllegalStateException].
 *
 * ### Filter ordering
 * This filter runs **before** [AuthFilter] (token authentication) so that cheap API key
 * validation fails fast before expensive JWT parsing.
 *
 * ### Enabling / disabling
 * Controlled by `group.phorus.security.filters.api-key.enabled` (default: `false`).
 *
 * @see ApiKeyContext
 * @see ApiKeyValidator
 * @see group.phorus.auth.commons.config.ApiKeyFilterConfiguration
 */
@AutoConfiguration
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
class ApiKeyFilter(
    private val securityConfiguration: SecurityConfiguration,
    validatorProvider: ObjectProvider<ApiKeyValidator>,
    metricsProvider: ObjectProvider<MetricsRecorder>,
) : CoWebFilter() {
    private val validator = validatorProvider.getIfAvailable()
    private val metrics = metricsProvider.getIfAvailable()

    init {
        val config = securityConfiguration.filters.apiKey
        require(config.ignoredPaths.isEmpty() || config.protectedPaths.isEmpty()) {
            "API key filter cannot have both ignored-paths and protected-paths configured. " +
            "Use ignored-paths to skip specific paths, or protected-paths to only filter specific paths."
        }
    }

    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        val config = securityConfiguration.filters.apiKey
        if (!config.enabled) return chain.filter(exchange)

        val path = exchange.request.path.value()
        val method = exchange.request.method

        if (shouldSkipPath(config.ignoredPaths, config.protectedPaths, path, method)) {
            return chain.filter(exchange)
        }

        val apiKey = exchange.request.headers.getFirst(config.header)
            ?: throw Unauthorized("API key is missing (expected header: ${config.header})")

        val contextData = metrics?.timeApiKeyAuthentication { validateKey(apiKey, exchange.request) }
            ?: validateKey(apiKey, exchange.request)

        return withContext(ApiKeyContext.context.asContextElement(value = contextData)) {
            chain.filter(exchange)
        }
    }

    private fun validateKey(apiKey: String, request: ServerHttpRequest?): ApiKeyContextData {
        val config = securityConfiguration.filters.apiKey
        val apiKeyBytes = apiKey.toByteArray()

        if (config.keys.isNotEmpty()) {
            val entry = config.keys.entries.find { (_, value) ->
                MessageDigest.isEqual(value.toByteArray(), apiKeyBytes)
            }
            if (entry != null) return ApiKeyContextData(keyId = entry.key)
        }

        if (validator != null) {
            val result = validator.validate(apiKey, request)
            if (result.valid) return ApiKeyContextData(keyId = result.keyId, metadata = result.metadata)
        }

        if (config.keys.isEmpty() && validator == null) throw IllegalStateException(
            "API key filter is enabled but no validation is configured. " +
            "Either set group.phorus.security.filters.api-key.keys or register an ApiKeyValidator bean."
        )

        throw Unauthorized("Invalid API key")
    }
}
