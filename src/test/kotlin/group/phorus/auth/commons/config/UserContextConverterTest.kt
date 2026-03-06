package group.phorus.auth.commons.config

import group.phorus.auth.commons.dtos.AuthData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.exception.handling.Unauthorized
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import java.util.*

/**
 * Unit tests for [UserContextConverter].
 *
 * Validates header validation logic and token parsing delegation.
 */
class UserContextConverterTest {

    companion object {
        private val TEST_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001")

        private val AUTH_DATA = AuthData(
            userId = TEST_USER_ID,
            tokenType = TokenType.ACCESS_TOKEN,
            jti = "test-jti",
            privileges = listOf("read", "write"),
            properties = emptyMap(),
        )

        private fun mockAuthenticator(returnData: AuthData = AUTH_DATA): Authenticator {
            val authenticator = mock<Authenticator>()
            whenever(authenticator.authenticate(any(), any())).thenReturn(returnData)
            return authenticator
        }
    }

    @Nested
    @DisplayName("Header validation")
    inner class HeaderValidation {

        @Test
        fun `throws Unauthorized when header is too short`() {
            val converter = UserContextConverter(mockAuthenticator())

            assertThrows<Unauthorized> {
                converter.convert("Bear")
            }
        }

        @Test
        fun `throws Unauthorized when header is exactly Bearer prefix length`() {
            val converter = UserContextConverter(mockAuthenticator())

            assertThrows<Unauthorized> {
                converter.convert("Bearer ")
            }
        }

        @Test
        fun `throws Unauthorized when Bearer prefix is missing`() {
            val converter = UserContextConverter(mockAuthenticator())

            assertThrows<Unauthorized> {
                converter.convert("Basic dXNlcjpwYXNz")
            }
        }

        @Test
        fun `throws Unauthorized for empty string`() {
            val converter = UserContextConverter(mockAuthenticator())

            assertThrows<Unauthorized> {
                converter.convert("")
            }
        }
    }

    @Nested
    @DisplayName("Token parsing delegation")
    inner class TokenParsing {

        @Test
        fun `extracts token after Bearer prefix and delegates to authenticator`() {
            val authenticator = mockAuthenticator()
            val converter = UserContextConverter(authenticator)

            converter.convert("Bearer my-jwt-token")

            verify(authenticator).authenticate(eq("my-jwt-token"), eq(false))
        }

        @Test
        fun `passes enableValidators as false`() {
            val authenticator = mockAuthenticator()
            val converter = UserContextConverter(authenticator)

            converter.convert("Bearer some-token")

            verify(authenticator).authenticate(any(), eq(false))
        }

        @Test
        fun `returns AuthContextData mapped from AuthData`() {
            val converter = UserContextConverter(mockAuthenticator())

            val result = converter.convert("Bearer valid-token")

            assertNotNull(result)
            assertEquals(TEST_USER_ID, result.userId)
        }

        @Test
        fun `propagates Unauthorized from authenticator`() {
            val authenticator = mock<Authenticator>()
            whenever(authenticator.authenticate(any(), any()))
                .thenThrow(Unauthorized("Invalid JWT Token"))

            val converter = UserContextConverter(authenticator)

            assertThrows<Unauthorized> {
                converter.convert("Bearer expired-token")
            }
        }
    }
}
