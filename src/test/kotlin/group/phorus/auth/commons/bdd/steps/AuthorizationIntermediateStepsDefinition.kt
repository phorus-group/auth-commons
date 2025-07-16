package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.dtos.AddressResponse
import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.dtos.DocumentResponse
import group.phorus.auth.commons.bdd.app.model.Address
import group.phorus.auth.commons.bdd.app.model.Document
import group.phorus.auth.commons.bdd.app.model.User
import group.phorus.auth.commons.bdd.app.repositories.AddressRepository
import group.phorus.auth.commons.bdd.app.repositories.DocumentRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.services.TokenFactory
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseRequestScenarioScope
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

class AuthorizationIntermediateStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val requestScenarioScope: BaseRequestScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val documentRepository: DocumentRepository,
    @Autowired private val addressRepository: AddressRepository,
    @Autowired private val userRepository: UserRepository,
    @Autowired private val tokenFactory: TokenFactory,
) {

    @Given("the caller is not owner but has admin privilege")
    fun `the caller is not owner but has admin privilege`() {
        runBlocking {
            // Create a different user to be the document owner
            val differentUser = User(
                name = "Different User",
                email = "different@email.com",
                passwordHash = "hashedPassword"
            )
            val savedDifferentUser = userRepository.saveAndFlush(differentUser)
            baseScenarioScope.objects["differentUser"] = savedDifferentUser.id!!.toString()

            // Create admin access token for current test user
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("admin")
            val properties = mapOf(
                "name" to "Admin Test User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with multiple authorization levels:")
    fun `the given Document exists with multiple authorization levels`(data: DataTable) {
        val differentUserId = baseScenarioScope.objects["differentUser"] as String

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = UUID.fromString(differentUserId)
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has finance privilege and department")
    fun `the caller has finance privilege and department`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("finance:read")
            val properties = mapOf(
                "department" to "finance",
                "name" to "Finance User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with financial data:")
    fun `the given Document exists with financial data`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                departmentId = it["departmentId"],
                financialData = it["financialData"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has finance privilege but wrong department")
    fun `the caller has finance privilege but wrong department`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("finance:read")
            val properties = mapOf(
                "department" to "hr",
                "name" to "HR User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the caller owns document but lacks field privilege")
    fun `the caller owns document but lacks field privilege`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("basic:user") // No special:field privilege
            val properties = mapOf(
                "name" to "Basic User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with field authorization:")
    fun `the given Document exists with field authorization`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                sensitiveInfo = it["sensitiveInfo"],
                fieldOnlyData = it["fieldOnlyData"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has read-only privileges")
    fun `the caller has read-only privileges`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("read:documents")
            val properties = mapOf(
                "name" to "Reader User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists for operation testing:")
    fun `the given Document exists for operation testing`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                readOnlyField = it["readOnlyField"],
                updateOnlyField = it["updateOnlyField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has the given Document for update:")
    fun `the caller has the given Document for update`(data: DataTable) {
        val document = data.asMaps().first().let {
            DocumentDTO(
                title = it["title"],
                content = it["content"]
            )
        }
        requestScenarioScope.request = document
    }

    @Given("the caller has minimal privileges")
    fun `the caller has minimal privileges`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("basic:user")
            val properties = mapOf(
                "name" to "Minimal User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Address exists with no authorization:")
    fun `the given Address exists with no authorization`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }
        val user = userRepository.findById(userId).get()

        val address = data.asMaps().first().let {
            Address(
                address = it["address"],
                user = user
            )
        }

        val savedAddress = addressRepository.saveAndFlush(address)
        baseScenarioScope.objects["addressResponse"] = savedAddress.mapTo<AddressResponse>()!!
        baseScenarioScope.objects["addressId"] = savedAddress.id!!.toString()
    }

    @Given("the caller has manager role but not admin")
    fun `the caller has manager role but not admin`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("manager")
            val properties = mapOf(
                "name" to "Manager User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with multiple field annotations:")
    fun `the given Document exists with multiple field annotations`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId,
                multiAuthField = it["multiAuthField"]
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has the given Document for creation:")
    fun `the caller has the given Document for creation`(data: DataTable) {
        val document = data.asMaps().first().let {
            DocumentDTO(
                title = it["title"],
                content = it["content"],
                sensitiveInfo = it["sensitiveInfo"]
            )
        }
        requestScenarioScope.request = document
    }

    @Given("the given Document exists for deletion:")
    fun `the given Document exists for deletion`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    @Given("the caller has no special privileges")
    fun `the caller has no special privileges`() {
        runBlocking {
            val currentUserId = UUID.fromString(baseScenarioScope.objects["userId"] as String)
            val privileges = listOf("basic:user")
            val properties = mapOf(
                "name" to "Basic User",
                "email" to "coretest@email.com"
            )

            val accessToken = tokenFactory.createAccessToken(
                userId = currentUserId,
                privileges = privileges,
                properties = properties
            )

            baseScenarioScope.objects["accessToken"] = "Bearer ${accessToken.token}"
        }
    }

    @Given("the given Document exists with empty definitions:")
    fun `the given Document exists with empty definitions`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { UUID.fromString(it) }

        val document = data.asMaps().first().let {
            Document(
                title = it["title"],
                content = it["content"],
                ownerId = userId
            )
        }

        val savedDocument = documentRepository.saveAndFlush(document)
        baseScenarioScope.objects["documentResponse"] = savedDocument.mapTo<DocumentResponse>()!!
        baseScenarioScope.objects["documentId"] = savedDocument.id!!.toString()
    }

    // THEN steps
    @Then("the financial data should be accessible")
    fun `the financial data should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.financialData)
    }

    @Then("the financial data should not be accessible")
    fun `the financial data should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNull(documentResponse.financialData)
    }

    @Then("the sensitive info should be accessible")
    fun `the sensitive info should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.sensitiveInfo)
    }

    @Then("the field only data should not be accessible")
    fun `the field only data should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNull(documentResponse.fieldOnlyData)
    }

    @Then("the read only field should be accessible")
    fun `the read only field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.readOnlyField)
    }

    @Then("the update only field should not be accessible")
    fun `the update only field should not be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNull(documentResponse.updateOnlyField)
    }

    @Then("the multi auth field should be accessible")
    fun `the multi auth field should be accessible`() {
        val documentResponse = responseScenarioScope.responseSpec!!
            .expectBody<DocumentResponse>().returnResult().responseBody!!

        assertNotNull(documentResponse.multiAuthField)
    }
}