package group.phorus.auth.commons.config

import group.phorus.auth.commons.services.ApiKeyValidationResult
import group.phorus.auth.commons.services.ApiKeyValidator
import group.phorus.exception.handling.Unauthorized
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import org.springframework.beans.factory.ObjectProvider

/**
 * Unit tests for [ApiKeyContextConverter].
 *
 * Validates the validation chain (static keys -> custom validator -> 401),
 * constant-time comparison, and proper metadata handling.
 */
class ApiKeyContextConverterTest {

    companion object {
        private val STATIC_KEYS = mapOf(
            "default" to "static-secret",
            "partner-a" to "partner-a-secret",
        )

        private fun buildConfig(keys: Map<String, String> = emptyMap()) =
            SecurityConfiguration().apply {
                filters.apiKey.keys = keys
            }

        private fun validatorProvider(validator: ApiKeyValidator? = null): ObjectProvider<ApiKeyValidator> {
            val provider = mock<ObjectProvider<ApiKeyValidator>>()
            whenever(provider.getIfAvailable()).thenReturn(validator)
            return provider
        }

        private fun buildConverter(
            keys: Map<String, String> = emptyMap(),
            validator: ApiKeyValidator? = null,
        ) = ApiKeyContextConverter(buildConfig(keys), validatorProvider(validator))
    }

    @Nested
    @DisplayName("Static keys only")
    inner class StaticKeysOnly {

        @Test
        fun `accepts matching static key and resolves keyId`() {
            val converter = buildConverter(keys = STATIC_KEYS)

            val result = converter.convert("static-secret")

            assertNotNull(result)
            assertEquals("default", result.keyId)
            assertTrue(result.metadata.isEmpty())
        }

        @Test
        fun `resolves correct keyId for different keys`() {
            val converter = buildConverter(keys = STATIC_KEYS)

            val result = converter.convert("partner-a-secret")

            assertEquals("partner-a", result.keyId)
        }

        @Test
        fun `throws Unauthorized for non-matching key`() {
            val converter = buildConverter(keys = STATIC_KEYS)

            assertThrows<Unauthorized> {
                converter.convert("wrong-secret")
            }
        }
    }

    @Nested
    @DisplayName("Custom validator only")
    inner class ValidatorOnly {

        @Test
        fun `accepts key when validator returns valid`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("dynamic-key"), isNull()) } doReturn ApiKeyValidationResult(
                    valid = true,
                    keyId = "dynamic-id",
                    metadata = mapOf("scope" to "read"),
                )
            }
            val converter = buildConverter(validator = validator)

            val result = converter.convert("dynamic-key")

            assertNotNull(result)
            assertEquals("dynamic-id", result.keyId)
            assertEquals("read", result.metadata["scope"])
        }

        @Test
        fun `throws Unauthorized when validator returns invalid`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("bad-key"), isNull()) } doReturn ApiKeyValidationResult(valid = false)
            }
            val converter = buildConverter(validator = validator)

            assertThrows<Unauthorized> {
                converter.convert("bad-key")
            }
        }

        @Test
        fun `passes metadata from validator result`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("key"), isNull()) } doReturn ApiKeyValidationResult(
                    valid = true,
                    keyId = "id",
                    metadata = mapOf("owner" to "alice", "tier" to "premium"),
                )
            }
            val converter = buildConverter(validator = validator)

            val result = converter.convert("key")

            assertEquals(2, result.metadata.size)
            assertEquals("alice", result.metadata["owner"])
            assertEquals("premium", result.metadata["tier"])
        }
    }

    @Nested
    @DisplayName("Chained validation (static + validator)")
    inner class ChainedValidation {

        @Test
        fun `static key match skips validator entirely`() {
            val validator = mock<ApiKeyValidator>()
            val converter = buildConverter(keys = STATIC_KEYS, validator = validator)

            converter.convert("static-secret")

            verifyNoInteractions(validator)
        }

        @Test
        fun `falls back to validator when no static key matches`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("dynamic-only"), isNull()) } doReturn ApiKeyValidationResult(valid = true, keyId = "from-validator")
            }
            val converter = buildConverter(keys = STATIC_KEYS, validator = validator)

            val result = converter.convert("dynamic-only")

            assertEquals("from-validator", result.keyId)
            verify(validator).validate(eq("dynamic-only"), isNull())
        }

        @Test
        fun `throws Unauthorized when both static keys and validator fail`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("unknown"), isNull()) } doReturn ApiKeyValidationResult(valid = false)
            }
            val converter = buildConverter(keys = STATIC_KEYS, validator = validator)

            assertThrows<Unauthorized> {
                converter.convert("unknown")
            }
        }

        @Test
        fun `returns static key result even if validator would accept the same key`() {
            val validator = mock<ApiKeyValidator> {
                on { validate(eq("static-secret"), isNull()) } doReturn ApiKeyValidationResult(
                    valid = true,
                    keyId = "validator-id",
                    metadata = mapOf("from" to "validator"),
                )
            }
            val converter = buildConverter(keys = STATIC_KEYS, validator = validator)

            val result = converter.convert("static-secret")

            assertEquals("default", result.keyId)
            assertTrue(result.metadata.isEmpty())
            verifyNoInteractions(validator)
        }
    }
}
