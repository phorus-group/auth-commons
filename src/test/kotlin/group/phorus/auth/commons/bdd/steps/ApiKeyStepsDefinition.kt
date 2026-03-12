package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.config.ApiKeyFilterConfiguration
import group.phorus.auth.commons.config.Path
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.java.After
import io.cucumber.java.Before
import io.cucumber.java.en.Then
import org.junit.jupiter.api.Assertions.assertEquals
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody

class ApiKeyStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val securityConfiguration: SecurityConfiguration,
) {
    private var originalApiKeyConfig: ApiKeyFilterConfiguration? = null
    private var originalTokenIgnoredPaths: List<Path>? = null

    @Before("@apikey and not @apikey-protected-paths")
    fun enableApiKeyFilter() {
        originalApiKeyConfig = securityConfiguration.filters.apiKey.copy()
        originalTokenIgnoredPaths = securityConfiguration.filters.token.ignoredPaths.toList()

        securityConfiguration.filters.apiKey.enabled = true
        securityConfiguration.filters.apiKey.header = "X-API-KEY"
        securityConfiguration.filters.apiKey.keys = mapOf(
            "default" to "test-default-key",
            "partner-a" to "partner-a-secret",
            "partner-b" to "partner-b-secret",
        )
        securityConfiguration.filters.apiKey.ignoredPaths = listOf(
            Path("/api-key-ignored/**"),
            Path("/auth/**"),
            Path("/user/**"),
            Path("/test/**"),
            Path("/products/{id:\\d+}"),
        )
        securityConfiguration.filters.apiKey.protectedPaths = emptyList()

        securityConfiguration.filters.token.ignoredPaths += listOf(Path("/api-key-protected/identity"), Path("/api-key-ignored/**"))
    }

    @Before("@apikey-protected-paths")
    fun enableApiKeyFilterWithProtectedPaths() {
        originalApiKeyConfig = securityConfiguration.filters.apiKey.copy()
        originalTokenIgnoredPaths = securityConfiguration.filters.token.ignoredPaths.toList()

        securityConfiguration.filters.apiKey.enabled = true
        securityConfiguration.filters.apiKey.header = "X-API-KEY"
        securityConfiguration.filters.apiKey.keys = mapOf(
            "default" to "test-default-key",
            "partner-a" to "partner-a-secret",
        )
        securityConfiguration.filters.apiKey.ignoredPaths = emptyList()
        securityConfiguration.filters.apiKey.protectedPaths = listOf(
            Path("/api-key-protected/**"),
        )

        securityConfiguration.filters.token.ignoredPaths += listOf(
            Path("/api-key-protected/identity"),
            Path("/api-key-ignored/**"),
        )
    }

    @After("@apikey")
    fun restoreApiKeyFilter() {
        originalApiKeyConfig?.let {
            securityConfiguration.filters.apiKey.enabled = it.enabled
            securityConfiguration.filters.apiKey.header = it.header
            securityConfiguration.filters.apiKey.keys = it.keys
            securityConfiguration.filters.apiKey.ignoredPaths = it.ignoredPaths
            securityConfiguration.filters.apiKey.protectedPaths = it.protectedPaths
        }
        originalTokenIgnoredPaths?.let {
            securityConfiguration.filters.token.ignoredPaths = it
        }
    }

    @Then("the response contains keyId {string}")
    fun `the response contains keyId`(expectedKeyId: String) {
        val body = getOrFetchApiKeyResponseBody()
        assertEquals(expectedKeyId, body["keyId"])
    }

    @Then("the response contains metadata key {string} with value {string}")
    fun `the response contains metadata key with value`(key: String, expectedValue: String) {
        val body = getOrFetchApiKeyResponseBody()
        @Suppress("UNCHECKED_CAST")
        val metadata = body["metadata"] as? Map<String, String>
        assertEquals(expectedValue, metadata?.get(key), "Expected metadata['$key'] to be '$expectedValue'")
    }

    @Then("the response does not contain metadata key {string}")
    fun `the response does not contain metadata key`(key: String) {
        val body = getOrFetchApiKeyResponseBody()
        @Suppress("UNCHECKED_CAST")
        val metadata = body["metadata"] as? Map<String, String>
        assertEquals(true, metadata == null || !metadata.containsKey(key), "Expected metadata to not contain key '$key'")
    }

    private fun getOrFetchApiKeyResponseBody(): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        val cached = baseScenarioScope.objects["apiKeyResponseBody"] as? Map<String, Any?>
        if (cached != null) return cached

        val body = responseScenarioScope.responseSpec!!
            .expectBody<Map<String, Any?>>().returnResult().responseBody!!
        baseScenarioScope.objects["apiKeyResponseBody"] = body
        return body
    }

    private fun ApiKeyFilterConfiguration.copy() = ApiKeyFilterConfiguration(
        enabled = this.enabled,
        header = this.header,
        keys = this.keys.toMap(),
        ignoredPaths = this.ignoredPaths.toList(),
        protectedPaths = this.protectedPaths.toList(),
    )
}
