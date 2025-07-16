package group.phorus.auth.commons.bdd.steps

import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import group.phorus.auth.commons.bdd.app.dtos.DocumentResponse
import group.phorus.auth.commons.bdd.app.model.Document
import group.phorus.auth.commons.bdd.app.repositories.DocumentRepository
import group.phorus.auth.commons.services.TokenFactory
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody
import java.util.*

class AuthorizationAdvancedStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val documentRepository: DocumentRepository,
    @Autowired private val tokenFactory: TokenFactory,
) {
    @Given("the caller has database and validation setup")
    fun `the caller has database and validation setup`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin", "validation:access")
            val properties = mapOf(
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com",
                "userAgent" to "TestAgent/1.0"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the caller has handler configuration with errors")
    fun `the caller has handler configuration with errors`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin")
            val properties = mapOf(
                "simulateError" to "true",
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }

        // Setup REST handler precedence
        val docId = baseScenarioScope.objects["documentId"] as? String ?: "test-doc-id"
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/precedence/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"result": "rest-wins"}""")
                )
        )
    }

    @Given("the caller has handler setup without validation")
    fun `the caller has handler setup without validation`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin")
            val properties = mapOf(
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }

        // Setup various handler responses
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/setup/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"setup": "completed"}""")
                )
        )

        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/response/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"data": "allowed"}""")
                )
        )

        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/handler/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"result": "success"}""")
                )
        )
    }

    @Given("the caller has context setup with organization data")
    fun `the caller has context setup with organization data`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin", "exists")
            val properties = mapOf(
                "organizationId" to "test-org-123",
                "department" to "engineering",
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with context fields:")
    fun `the given Document exists with context fields`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                authContextField = it["authContextField"],
                httpContextField = it["httpContextField"],
                entityContextField = it["entityContextField"],
                templateField = it["templateField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has varied privilege levels")
    fun `the caller has varied privilege levels`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin", "manager", "exists")
            val properties = mapOf(
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with value matches tests:")
    fun `the given Document exists with value matches tests`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                valueMatchField = it["valueMatchField"],
                onlyMatchField = it["onlyMatchField"],
                onlyValueField = it["onlyValueField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the external service supports all HTTP methods")
    fun `the external service supports all HTTP methods`() {
        // GET handler
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/permissions/get/.*/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "true"}""")
                )
        )

        // POST handler
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.post(WireMock.urlMatching("/api/permissions/post/.*/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "true"}""")
                )
        )

        // No auth handler
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/permissions/noauth/.*"))
                .withHeader("Authorization", WireMock.absent())
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "true"}""")
                )
        )
    }

    @Given("the given Document exists with REST handler fields:")
    fun `the given Document exists with REST handler fields`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                getHandlerField = it["getHandlerField"],
                postHandlerField = it["postHandlerField"],
                noAuthField = it["noAuthField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the external service is unreliable")
    fun `the external service is unreliable`() {
        // Timeout endpoint
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/slow/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withFixedDelay(6000)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "true"}""")
                )
        )

        // Network error endpoint
        AuthorizationStepsDefinition.wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/error/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)
                )
        )
    }

    @Given("the given Document exists with error handling fields:")
    fun `the given Document exists with error handling fields`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                timeoutField = it["timeoutField"],
                networkErrorField = it["networkErrorField"],
                invalidUrlField = it["invalidUrlField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the given Document exists with custom handler fields:")
    fun `the given Document exists with custom handler fields`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                databaseField = it["databaseField"],
                validationField = it["validationField"],
                chainedField = it["chainedField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the given Document exists with handler error tests:")
    fun `the given Document exists with handler error tests`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                errorHandlerField = it["errorHandlerField"],
                saveToField = it["saveToField"],
                precedenceField = it["precedenceField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has template test setup")
    fun `the caller has template test setup`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin")
            val properties = mapOf(
                "nested/${currentUserId}/value" to "nested-test",
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with template edge cases:")
    fun `the given Document exists with template edge cases`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                validTemplateField = it["validTemplateField"],
                invalidTemplateField = it["invalidTemplateField"],
                nestedTemplateField = it["nestedTemplateField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has organization context with priority setup")
    fun `the caller has organization context with priority setup`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("org:access", "role:manager")
            val properties = mapOf(
                "organizationId" to "test-org-456",
                "department" to "engineering",
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with organization context:")
    fun `the given Document exists with organization context`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                orgDataField = it["orgDataField"],
                orgPermissionField = it["orgPermissionField"],
                orgRoleField = it["orgRoleField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the given Document exists with handler contexts:")
    fun `the given Document exists with handler contexts`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                setupField = it["setupField"],
                responseField = it["responseField"],
                handlerField = it["handlerField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has standard privileges")
    fun `the caller has standard privileges`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("user:standard")
            val properties = mapOf(
                "name" to "Advanced Test User",
                "email" to "advancedtest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with invalid contexts:")
    fun `the given Document exists with invalid contexts`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                invalidContextField = it["invalidContextField"],
                missingFieldRef = it["missingFieldRef"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    // THEN steps (keeping all existing THEN steps)
    @Then("all context fields should be accessible")
    fun `all context fields should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.authContextField)
        assertNotNull(documentResponse.httpContextField)
        assertNotNull(documentResponse.entityContextField)
        assertNotNull(documentResponse.templateField)
    }

    @Then("the value match field should be accessible")
    fun `the value match field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.valueMatchField)
    }

    @Then("the only match field should be accessible")
    fun `the only match field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.onlyMatchField)
    }

    @Then("the only value field should be accessible")
    fun `the only value field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.onlyValueField)
    }

    @Then("the GET handler field should be accessible")
    fun `the GET handler field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.getHandlerField)
    }

    @Then("the POST handler field should be accessible")
    fun `the POST handler field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.postHandlerField)
    }

    @Then("the no auth field should be accessible")
    fun `the no auth field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.noAuthField)
    }

    @Then("the timeout field should not be accessible")
    fun `the timeout field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.timeoutField)
    }

    @Then("the network error field should not be accessible")
    fun `the network error field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.networkErrorField)
    }

    @Then("the invalid url field should not be accessible")
    fun `the invalid url field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.invalidUrlField)
    }

    @Then("the database field should be accessible")
    fun `the database field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.databaseField)
    }

    @Then("the validation field should be accessible")
    fun `the validation field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.validationField)
    }

    @Then("the chained field should be accessible")
    fun `the chained field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.chainedField)
    }

    @Then("the error handler field should not be accessible")
    fun `the error handler field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.errorHandlerField)
    }

    @Then("the saveTo field should be accessible")
    fun `the saveTo field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.saveToField)
    }

    @Then("the precedence field should be accessible")
    fun `the precedence field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.precedenceField)
    }

    @Then("the valid template field should be accessible")
    fun `the valid template field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.validTemplateField)
    }

    @Then("the invalid template field should not be accessible")
    fun `the invalid template field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.invalidTemplateField)
    }

    @Then("the nested template field should be accessible")
    fun `the nested template field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.nestedTemplateField)
    }

    @Then("the org data field should be accessible")
    fun `the org data field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.orgDataField)
    }

    @Then("the org permission field should be accessible")
    fun `the org permission field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.orgPermissionField)
    }

    @Then("the org role field should be accessible")
    fun `the org role field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.orgRoleField)
    }

    @Then("the setup field should be accessible")
    fun `the setup field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.setupField)
    }

    @Then("the response field should be accessible")
    fun `the response field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.responseField)
    }

    @Then("the handler field should be accessible")
    fun `the handler field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNotNull(documentResponse.handlerField)
    }

    @Then("the invalid context field should not be accessible")
    fun `the invalid context field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.invalidContextField)
    }

    @Then("the missing field ref should not be accessible")
    fun `the missing field ref should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!
        assertNull(documentResponse.missingFieldRef)
    }
}