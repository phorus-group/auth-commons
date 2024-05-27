package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.dtos.UserDTO
import group.phorus.auth.commons.bdd.app.dtos.UserResponse
import group.phorus.auth.commons.bdd.app.model.User
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseRequestScenarioScope
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody


class UserStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val requestScenarioScope: BaseRequestScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val userRepository: UserRepository,
) {
    @Given("the given User exists:")
    fun `the given User exists`(data: DataTable) {
        val user = data.asMaps().first().let {
            User(
                name = it["name"],
                email = it["email"],
                passwordHash = it["passwordHash"],
            )
        }

        baseScenarioScope.objects["userResponse"] = userRepository.saveAndFlush(user).mapTo<UserResponse>()!!
        baseScenarioScope.objects["userId"] = (baseScenarioScope.objects["userResponse"] as UserResponse).id!!.toString()
    }

    @Given("the caller has the given User:")
    fun `the caller has the given User`(data: DataTable) {
        val user = data.asMaps().first().let {
            UserDTO(
                name = it["name"],
                email = it["email"],
                password = it["password"],
            )
        }

        requestScenarioScope.request = user
    }


    @Then("the service returns the User:")
    fun `the service returns the User`(data: DataTable) {
        val userResponse = responseScenarioScope.responseSpec!!
            .expectBody<UserResponse>().returnResult().responseBody!!

        assertNotNull(userResponse.id)
        assertEquals(data.asMaps().first()["name"], userResponse.name)
        assertEquals(data.asMaps().first()["email"], userResponse.email)

        baseScenarioScope.objects["userResponse"] = userResponse
        baseScenarioScope.objects["userId"] = (baseScenarioScope.objects["userResponse"] as UserResponse).id!!.toString()
    }

    @Then("the service returns a message with the error message {string}")
    fun `the service returns a message with the error {string}`(error: String) {
        responseScenarioScope.responseSpec!!
            .expectBody()
            .jsonPath("$.apierror.message").isEqualTo(error)
    }
}