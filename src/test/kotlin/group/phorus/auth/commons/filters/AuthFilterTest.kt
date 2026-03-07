package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.AuthMode
import group.phorus.auth.commons.config.MetricsRecorder
import group.phorus.auth.commons.config.Path
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.dtos.AuthData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.impl.IdpAuthenticator
import group.phorus.exception.handling.Unauthorized
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import org.springframework.beans.factory.ObjectProvider
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.util.*

/**
 * Unit tests for [AuthFilter].
 *
 * Validates header extraction, path filtering, mode-based routing,
 * and refresh token path enforcement.
 *
 * Since [AuthFilter] extends [CoWebFilter][org.springframework.web.server.CoWebFilter],
 * the coroutine `filter` method is protected. Tests invoke the public
 * [WebFilter.filter] entry point instead.
 */
class AuthFilterTest {

    companion object {
        private val TEST_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001")

        private val ACCESS_AUTH_DATA = AuthData(
            userId = TEST_USER_ID,
            tokenType = TokenType.ACCESS_TOKEN,
            jti = "test-jti",
            privileges = listOf("read"),
            properties = emptyMap(),
        )

        private val REFRESH_AUTH_DATA = AuthData(
            userId = TEST_USER_ID,
            tokenType = TokenType.REFRESH_TOKEN,
            jti = "test-jti-refresh",
            privileges = emptyList(),
            properties = emptyMap(),
        )

        private fun buildConfig(
            mode: AuthMode = AuthMode.STANDALONE,
            ignoredPaths: List<Path> = emptyList(),
            refreshTokenPath: String? = null,
        ) = SecurityConfiguration(
            mode = mode,
            ignoredPaths = ignoredPaths,
            refreshTokenPath = refreshTokenPath,
        )

        private fun mockAuthenticator(returnData: AuthData = ACCESS_AUTH_DATA): Authenticator {
            val authenticator = mock<Authenticator>()
            whenever(authenticator.authenticate(any(), any())).thenReturn(returnData)
            return authenticator
        }

        private fun mockIdpAuthenticator(returnData: AuthData = ACCESS_AUTH_DATA): IdpAuthenticator {
            val idpAuth = mock<IdpAuthenticator>()
            whenever(idpAuth.authenticate(any(), any())).thenReturn(returnData)
            return idpAuth
        }

        private fun buildExchange(
            path: String = "/api/test",
            method: HttpMethod = HttpMethod.GET,
            authHeader: String? = "Bearer valid-token",
        ): ServerWebExchange {
            val requestBuilder = MockServerHttpRequest.method(method, path)
            if (authHeader != null) {
                requestBuilder.header(HttpHeaders.AUTHORIZATION, authHeader)
            }
            return MockServerWebExchange.from(requestBuilder.build())
        }

        private fun emptyMetricsProvider(): ObjectProvider<MetricsRecorder> = mock()

        private fun noOpChain(): WebFilterChain =
            WebFilterChain { Mono.empty() }

        /**
         * Invokes the filter through the public [WebFilter] interface and blocks for the result.
         * Errors surface as thrown exceptions so assertions can catch them directly.
         */
        private fun invokeFilter(filter: AuthFilter, exchange: ServerWebExchange) {
            filter.filter(exchange, noOpChain()).block()
        }
    }

    @Nested
    @DisplayName("Header extraction")
    inner class HeaderExtraction {

        @Test
        fun `throws Unauthorized when Authorization header is missing`() {
            val config = buildConfig()
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())
            val exchange = buildExchange(authHeader = null)

            assertThrows<Unauthorized> { invokeFilter(filter, exchange) }
        }

        @Test
        fun `throws Unauthorized when Authorization header is too short`() {
            val config = buildConfig()
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())
            val exchange = buildExchange(authHeader = "Bear")

            assertThrows<Unauthorized> { invokeFilter(filter, exchange) }
        }

        @Test
        fun `throws Unauthorized when Bearer prefix is missing`() {
            val config = buildConfig()
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())
            val exchange = buildExchange(authHeader = "Basic dXNlcjpwYXNz")

            assertThrows<Unauthorized> { invokeFilter(filter, exchange) }
        }

        @Test
        fun `extracts token after Bearer prefix`() {
            val authenticator = mockAuthenticator()
            val config = buildConfig()
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())
            val exchange = buildExchange(authHeader = "Bearer my-jwt-token")

            invokeFilter(filter, exchange)

            verify(authenticator).authenticate(eq("my-jwt-token"), any())
        }
    }

    @Nested
    @DisplayName("Path filtering")
    inner class PathFiltering {

        @Test
        fun `bypasses authentication for ignored paths`() {
            val config = buildConfig(ignoredPaths = listOf(Path(path = "/auth/login")))
            val authenticator = mockAuthenticator()
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())
            val exchange = buildExchange(path = "/auth/login", authHeader = null)

            invokeFilter(filter, exchange)

            verifyNoInteractions(authenticator)
        }

        @Test
        fun `bypasses authentication for ignored path with matching method`() {
            val config = buildConfig(ignoredPaths = listOf(Path(path = "/auth/login", method = "POST")))
            val authenticator = mockAuthenticator()
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())
            val exchange = buildExchange(path = "/auth/login", method = HttpMethod.POST, authHeader = null)

            invokeFilter(filter, exchange)

            verifyNoInteractions(authenticator)
        }

        @Test
        fun `does not bypass when method does not match ignored path`() {
            val config = buildConfig(ignoredPaths = listOf(Path(path = "/auth/login", method = "POST")))
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())
            val exchange = buildExchange(path = "/auth/login", method = HttpMethod.GET, authHeader = null)

            assertThrows<Unauthorized> { invokeFilter(filter, exchange) }
        }

        @Test
        fun `does not bypass for non-matching paths`() {
            val config = buildConfig(ignoredPaths = listOf(Path(path = "/auth/login")))
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())
            val exchange = buildExchange(path = "/api/protected", authHeader = null)

            assertThrows<Unauthorized> { invokeFilter(filter, exchange) }
        }
    }

    @Nested
    @DisplayName("Mode-based routing")
    inner class ModeRouting {

        @Test
        fun `uses Authenticator in STANDALONE mode`() {
            val authenticator = mockAuthenticator()
            val idpAuth = mockIdpAuthenticator()
            val config = buildConfig(mode = AuthMode.STANDALONE)
            val filter = AuthFilter(config, authenticator, idpAuth, emptyMetricsProvider())

            invokeFilter(filter, buildExchange())

            verify(authenticator).authenticate(any(), any())
            verifyNoInteractions(idpAuth)
        }

        @Test
        fun `uses Authenticator in IDP_BRIDGE mode`() {
            val authenticator = mockAuthenticator()
            val idpAuth = mockIdpAuthenticator()
            val config = buildConfig(mode = AuthMode.IDP_BRIDGE)
            val filter = AuthFilter(config, authenticator, idpAuth, emptyMetricsProvider())

            invokeFilter(filter, buildExchange())

            verify(authenticator).authenticate(any(), any())
            verifyNoInteractions(idpAuth)
        }

        @Test
        fun `uses IdpAuthenticator in IDP_DELEGATED mode`() {
            val authenticator = mockAuthenticator()
            val idpAuth = mockIdpAuthenticator()
            val config = buildConfig(mode = AuthMode.IDP_DELEGATED)
            val filter = AuthFilter(config, authenticator, idpAuth, emptyMetricsProvider())

            invokeFilter(filter, buildExchange())

            verify(idpAuth).authenticate(any(), any())
            verify(authenticator, never()).authenticate(any(), any())
        }

        @Test
        fun `throws IllegalStateException in IDP_DELEGATED without IdpAuthenticator`() {
            val config = buildConfig(mode = AuthMode.IDP_DELEGATED)
            val filter = AuthFilter(config, mockAuthenticator(), null, emptyMetricsProvider())

            assertThrows<IllegalStateException> { invokeFilter(filter, buildExchange()) }
        }
    }

    @Nested
    @DisplayName("Refresh token enforcement")
    inner class RefreshTokenEnforcement {

        @Test
        fun `rejects refresh token when refreshTokenPath is not configured`() {
            val authenticator = mockAuthenticator(REFRESH_AUTH_DATA)
            val config = buildConfig(refreshTokenPath = null)
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(path = "/api/something"))
            }
        }

        @Test
        fun `rejects refresh token on non-matching path`() {
            val authenticator = mockAuthenticator(REFRESH_AUTH_DATA)
            val config = buildConfig(refreshTokenPath = "/auth/token")
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())

            assertThrows<Unauthorized> {
                invokeFilter(filter, buildExchange(path = "/api/something"))
            }
        }

        @Test
        fun `allows refresh token on matching path`() {
            val authenticator = mockAuthenticator(REFRESH_AUTH_DATA)
            val config = buildConfig(refreshTokenPath = "/auth/token")
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())

            invokeFilter(filter, buildExchange(path = "/auth/token"))
        }

        @Test
        fun `allows access token on any path`() {
            val authenticator = mockAuthenticator(ACCESS_AUTH_DATA)
            val config = buildConfig(refreshTokenPath = "/auth/token")
            val filter = AuthFilter(config, authenticator, null, emptyMetricsProvider())

            invokeFilter(filter, buildExchange(path = "/api/anything"))
        }
    }
}
