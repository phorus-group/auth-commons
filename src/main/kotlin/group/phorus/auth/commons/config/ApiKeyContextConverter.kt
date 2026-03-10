package group.phorus.auth.commons.config

import group.phorus.auth.commons.dtos.ApiKeyContextData
import group.phorus.auth.commons.services.ApiKeyValidator
import group.phorus.exception.handling.Unauthorized
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.core.convert.converter.Converter
import java.security.MessageDigest

/**
 * Spring [Converter] that transforms a raw API key header value into [ApiKeyContextData].
 *
 * This enables controller parameter injection via `@RequestHeader`:
 *
 * ```kotlin
 * @GetMapping("/webhook")
 * suspend fun webhook(
 *     @RequestHeader("X-API-KEY") apiKey: ApiKeyContextData,
 * ): Response {
 *     println(apiKey.keyId)
 * }
 * ```
 *
 * The validation chain is the same as [group.phorus.auth.commons.filters.ApiKeyFilter]:
 * static keys first, then custom [ApiKeyValidator], then 401.
 *
 * @see group.phorus.auth.commons.filters.ApiKeyFilter
 * @see ApiKeyContextData
 */
@AutoConfiguration
class ApiKeyContextConverter(
    private val securityConfiguration: SecurityConfiguration,
    validatorProvider: ObjectProvider<ApiKeyValidator>,
) : Converter<String, ApiKeyContextData> {
    private val validator = validatorProvider.getIfAvailable()

    override fun convert(apiKey: String): ApiKeyContextData {
        val config = securityConfiguration.filters.apiKey
        val apiKeyBytes = apiKey.toByteArray()

        if (config.keys.isNotEmpty()) {
            val entry = config.keys.entries.find { (_, value) ->
                MessageDigest.isEqual(value.toByteArray(), apiKeyBytes)
            }
            if (entry != null) return ApiKeyContextData(keyId = entry.key)
        }

        if (validator != null) {
            val result = validator.validate(apiKey)
            if (result.valid) return ApiKeyContextData(keyId = result.keyId, metadata = result.metadata)
        }

        throw Unauthorized("Invalid API key")
    }
}
