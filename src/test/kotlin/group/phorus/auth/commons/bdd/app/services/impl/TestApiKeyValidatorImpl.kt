package group.phorus.auth.commons.bdd.app.services.impl

import group.phorus.auth.commons.services.ApiKeyValidationResult
import group.phorus.auth.commons.services.ApiKeyValidator
import org.springframework.stereotype.Service

@Service
class TestApiKeyValidatorImpl : ApiKeyValidator {

    private val validKeys = mapOf(
        "dynamic-key-123" to ApiKeyValidationResult(
            valid = true,
            keyId = "dynamic-partner",
            metadata = mapOf(
                "partnerId" to "partner-dynamic",
                "tier" to "premium"
            )
        ),
        "webhook-key-456" to ApiKeyValidationResult(
            valid = true,
            keyId = "webhook-service",
            metadata = mapOf(
                "service" to "webhooks",
                "environment" to "test"
            )
        )
    )

    override fun validate(apiKey: String): ApiKeyValidationResult {
        return validKeys[apiKey] ?: ApiKeyValidationResult(valid = false)
    }
}
