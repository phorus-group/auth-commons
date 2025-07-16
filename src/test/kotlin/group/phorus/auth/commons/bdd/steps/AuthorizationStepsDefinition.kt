package group.phorus.auth.commons.bdd.steps

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.dtos.DocumentResponse
import group.phorus.auth.commons.bdd.app.model.Document
import group.phorus.auth.commons.bdd.app.model.User
import group.phorus.auth.commons.bdd.app.repositories.DocumentRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.security.TokenFactory
import group.phorus.auth.commons.services.TokenFactory
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseRequestScenarioScope
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.AfterAll
import io.cucumber.java.BeforeAll
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody
import java.util.*

class AuthorizationStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val requestScenarioScope: BaseRequestScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val documentRepository: DocumentRepository,
    @Autowired private val userRepository: UserRepository,
    @Autowired private val tokenFactory: TokenFactory,
) {

    companion object {
        val wireMockServer = WireMockServer(8088)
    }

    @Given("the caller has admin privileges")
    fun `the caller has admin privileges`() {
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
    }

    @Given("the given Document exists:")
    fun `the given Document exists`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                sensitiveInfo = it["sensitiveInfo"],
                restrictedData = it["restrictedData"],
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has the given Document:")
    fun `the caller has the given Document`(data: DataTable) {
        val document = data.asMaps().first().let {
            DocumentDTO(
                title = it["title"],
                content = it["content"],
                sensitiveInfo = it["sensitiveInfo"],
                restrictedData = it["restrictedData"],
            )
        }

        requestScenarioScope.request = document
    }

    @Given("the external permission service allows access for document {string}")
    fun `the external permission service allows access for document`(documentId: String) {
        val docId = baseScenarioScope.objects[documentId] ?: documentId
        val userId = baseScenarioScope.objects["userId"] as String

        wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/permissions/document/$docId/user/$userId"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "true", "documentId": "$docId", "userId": "$userId"}""")
                )
        )
    }

    @Given("the external permission service denies access for document {string}")
    fun `the external permission service denies access for document`(documentId: String) {
        val docId = baseScenarioScope.objects[documentId] ?: documentId
        val userId = baseScenarioScope.objects["userId"] as String

        wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/permissions/document/$docId/user/$userId"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"canAccess": "false", "reason": "Access denied"}""")
                )
        )
    }

    @Given("the external permission service is unavailable")
    fun `the external permission service is unavailable`() {
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlMatching("/api/permissions/document/.*/user/.*"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(503)
                        .withHeader(ContentTypeHeader.KEY, "application/json")
                        .withBody("""{"error": "Service unavailable"}""")
                )
        )
    }

    @Then("the service returns the Document")
    fun `the service returns the Document`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.id)
        baseScenarioScope.objects["documentResponse"] = documentResponse
        baseScenarioScope.objects["documentId"] = documentResponse.id!!.toString()
    }

    @Then("the service returns the Document with accessible fields")
    fun `the service returns the Document with accessible fields`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.id)
        assertNotNull(documentResponse.title)
        assertNotNull(documentResponse.content)

        baseScenarioScope.objects["documentResponse"] = documentResponse
    }

    @Then("the service returns the Document without sensitive fields")
    fun `the service returns the Document without sensitive fields`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.id)
        assertNotNull(documentResponse.title)
        assertNull(documentResponse.sensitiveInfo) // Should be null due to authorization

        baseScenarioScope.objects["documentResponse"] = documentResponse
    }

    @Then("the service returns the Document with restricted data")
    fun `the service returns the Document with restricted data`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.id)
        assertNotNull(documentResponse.title)
        assertNotNull(documentResponse.restrictedData) // Should be accessible via REST handler

        baseScenarioScope.objects["documentResponse"] = documentResponse
    }

    @Then("the service returns the Document without restricted data")
    fun `the service returns the Document without restricted data`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.id)
        assertNotNull(documentResponse.title)
        assertNull(documentResponse.restrictedData) // Should be null due to failed REST handler authorization

        baseScenarioScope.objects["documentResponse"] = documentResponse
    }
}

@BeforeAll
fun setupAuthorization() {
    AuthorizationStepsDefinition.wireMockServer.start()

    // Default stub for permission checks - denies access by default
    AuthorizationStepsDefinition.wireMockServer.stubFor(
        WireMock.get(WireMock.urlMatching("/api/permissions/document/.*/user/.*"))
            .willReturn(
                WireMock.aResponse()
                    .withStatus(200)
                    .withHeader(ContentTypeHeader.KEY, "application/json")
                    .withBody("""{"canAccess": "false", "reason": "Default deny"}""")
            )
    )
}

@AfterAll
fun teardownAuthorization() {
    AuthorizationStepsDefinition.wireMockServer.stop()
}