package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.MetricsRecorder
import group.phorus.auth.commons.config.Path
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.services.ApiKeyValidationResult
import group.phorus.auth.commons.services.ApiKeyValidator
import group.phorus.exception.handling.Unauthorized
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import org.springframework.beans.factory.ObjectProvider
import org.springframework.http.HttpMethod
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * Unit tests for [ApiKeyFilter].
 *
 * Validates the validation chain (static keys -> custom validator -> 401),
 * path filtering, enabled/disabled behavior, and misconfiguration detection.
 *
 * Since [ApiKeyFilter] extends [CoWebFilter][org.springframework.web.server.CoWebFilter],
 * the coroutine `filter` method is protected. Tests invoke the public
 * [WebFilter.filter] entry point instead.
 */
class ApiKeyFilterTest {

    companion object {
        private const val HEADER = "X-API-KEY"

        private val STATIC_KEYS = mapOf(
            "default" to "static-secret",
            "partner-a" to "partner-a-secret",
        )

        private fun buildConfig(
            enabled: Boolean = true,
            keys: Map<String, String> = emptyMap(),
            ignoredPaths: List<Path> = emptyList(),
            protectedPaths: List<Path> = emptyList(),
        ) = SecurityConfiguration().apply {
            filters.apiKey.enabled = enabled
            filters.apiKey.header = HEADER
            filters.apiKey.keys = keys
            filters.apiKey.ignoredPaths = ignoredPaths
            filters.apiKey.protectedPaths = protectedPaths
        }

        private fun validatorProvider(validator: ApiKeyValidator? = null): ObjectProvider<ApiKeyValidator> {
            val provider = mock<ObjectProvider<ApiKeyValidator>>()
            whenever(provider.getIfAvailable()).thenReturn(validator)
            return provider
        }

        private fun emptyMetricsProvider(): ObjectProvider<MetricsRecorder> = mock()

        private fun buildExchange(
            path: String = "/api/test",
            method: HttpMethod = HttpMethod.GET,
            apiKeyHeader: String? = null,
        ): ServerWebExchange {
            val requestBuilder = MockServerHttpRequest.method(method, path)
            if (apiKeyHeader != null) {
                requestBuilder.header(HEADER, apiKeyHeader)
            }
            return MockServerWebExchange.from(requestBuilder.build())
        }

        private fun noOpChain(): WebFilterChain =
            WebFilterChain { Mono.empty() }

        private fun invokeFilter(filter: ApiKeyFilter, exchange: ServerWebExchange) {
            filter.filter(exchange, noOpChain()).block()
        }
    }

    @Nested
    @DisplayName("Static keys only")
    inner class StaticKeysOnly {

        @Test
        fun `accepts matching static key and resolves key id`() {
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(apiKeyHeader = "static-secret"))
        }

        @Test
        fun `rejects non-matching key with 401`() {
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(apiKeyHeader = "wrong-key"))
            }
        }
    }

    @Nested
    @DisplayName("Custom validator only")
    inner class ValidatorOnly {

        @Test
        fun `accepts key when validator returns valid`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("dynamic-key"), any()) } doReturn ApiKeyValidationResult(
                    valid = true,
                    keyId = "dynamic-id",
                    metadata = mapOf("scope" to "read"),
                )
            }
            val config = buildConfig()
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(apiKeyHeader = "dynamic-key"))

            verify(validator).validate(eq("dynamic-key"), any())
        }

        @Test
        fun `rejects key when validator returns invalid`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("bad-key"), any()) } doReturn ApiKeyValidationResult(valid = false)
            }
            val config = buildConfig()
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(apiKeyHeader = "bad-key"))
            }
        }
    }

    @Nested
    @DisplayName("Chained validation (static keys + validator)")
    inner class ChainedValidation {

        @Test
        fun `static key match skips validator entirely`() {
            val validator = mock<ApiKeyValidator>()
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(apiKeyHeader = "static-secret"))

            verifyNoInteractions(validator)
        }

        @Test
        fun `falls back to validator when no static key matches`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("dynamic-only"), any()) } doReturn ApiKeyValidationResult(valid = true, keyId = "from-validator")
            }
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(apiKeyHeader = "dynamic-only"))

            verify(validator).validate(eq("dynamic-only"), any())
        }

        @Test
        fun `rejects with 401 when both static keys and validator fail`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("unknown"), any()) } doReturn ApiKeyValidationResult(valid = false)
            }
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(apiKeyHeader = "unknown"))
            }
        }
    }

    @Nested
    @DisplayName("Filter behavior")
    inner class FilterBehavior {

        @Test
        fun `skips filter when disabled`() {
            val validator = mock<ApiKeyValidator>()
            val config = buildConfig(enabled = false, keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(validator), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(apiKeyHeader = null))

            verifyNoInteractions(validator)
        }

        @Test
        fun `bypasses authentication for ignored paths`() {
            val config = buildConfig(keys = STATIC_KEYS, ignoredPaths = listOf(Path("/public")))
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(path = "/public/data", apiKeyHeader = null))
        }

        @Test
        fun `throws Unauthorized when header is missing`() {
            val config = buildConfig(keys = STATIC_KEYS)
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(apiKeyHeader = null))
            }
        }

        @Test
        fun `throws IllegalStateException when no validation is configured`() {
            val config = buildConfig()
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            assertThrows<IllegalStateException> {
                invokeFilter(filter, buildExchange(apiKeyHeader = "any-key"))
            }
        }
    }

    @Nested
    @DisplayName("Protected paths")
    inner class ProtectedPaths {

        @Test
        fun `filters matching protected path`() {
            val config = buildConfig(keys = STATIC_KEYS, protectedPaths = listOf(Path("/api/secure")))
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(path = "/api/secure/data", apiKeyHeader = null))
            }
        }

        @Test
        fun `skips non-matching protected path`() {
            val config = buildConfig(keys = STATIC_KEYS, protectedPaths = listOf(Path("/api/secure")))
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(path = "/public/data", apiKeyHeader = null))
        }

        @Test
        fun `protected path with method only filters matching method`() {
            val config = buildConfig(keys = STATIC_KEYS, protectedPaths = listOf(Path("/api/secure", method = "POST")))
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            invokeFilter(filter, buildExchange(path = "/api/secure/data", method = HttpMethod.GET, apiKeyHeader = null))
        }

        @Test
        fun `protected path with method filters matching method`() {
            val config = buildConfig(keys = STATIC_KEYS, protectedPaths = listOf(Path("/api/secure", method = "POST")))
            val filter = ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(path = "/api/secure/data", method = HttpMethod.POST, apiKeyHeader = null))
            }
        }

        @Test
        fun `throws IllegalArgumentException at startup when both ignoredPaths and protectedPaths are set`() {
            val config = buildConfig(
                keys = STATIC_KEYS,
                ignoredPaths = listOf(Path("/ignored")),
                protectedPaths = listOf(Path("/protected")),
            )

            assertThrows<IllegalArgumentException> {
                ApiKeyFilter(config, validatorProvider(), emptyMetricsProvider())
            }
        }
    }
}
