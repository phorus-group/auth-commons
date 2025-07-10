package group.phorus.auth.commons.bdd.steps

/**
 * Step definitions for core authorization functionality.
 * 
 * Tests:
 * - Multiple @Authorization annotations with priority ordering
 * - AuthorizationMode.AND and OR logic
 * - Field-level authorization inheritance and restrictions
 * - Operation-specific authorization (CREATE/READ/UPDATE/DELETE)
 * - Empty authorization and empty definitions
 */

import group.phorus.auth.commons.bdd.app.dtos.AddressResponse
import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.dtos.DocumentResponse
import group.phorus.auth.commons.bdd.app.model.Address
import group.phorus.auth.commons.bdd.app.model.Document
import group.phorus.auth.commons.bdd.app.repositories.AddressRepository
import group.phorus.auth.commons.bdd.app.repositories.DocumentRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.dtos.AuthContextData
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseRequestScenarioScope
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
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
) {
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = currentAuth.privileges + "finance:read",
            properties = currentAuth.properties + ("department" to "finance")
        )
        AuthContext.context.set(modifiedAuth)
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = currentAuth.privileges + "finance:read",
            properties = currentAuth.properties + ("department" to "hr")
        )
        AuthContext.context.set(modifiedAuth)
    }

    @Given("the caller owns document but lacks field privilege")
    fun `the caller owns document but lacks field privilege`() {
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = listOf("basic:user"), // No special:field privilege
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = listOf("read:documents"),
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = listOf("basic:user"),
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = listOf("manager"),
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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

    @Given("the caller has create privileges and field access")
    fun `the caller has create privileges and field access`() {
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = currentAuth.privileges + "admin", // Admin has all access
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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

    @Given("the caller has delete privileges")
    fun `the caller has delete privileges`() {
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = currentAuth.privileges + "admin", // Admin can delete
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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
        val currentAuth = AuthContext.context.get()
        val modifiedAuth = AuthContextData(
            userId = currentAuth.userId,
            privileges = listOf("basic:user"),
            properties = currentAuth.properties
        )
        AuthContext.context.set(modifiedAuth)
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