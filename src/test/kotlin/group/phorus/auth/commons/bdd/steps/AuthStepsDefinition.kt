package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.dtos.AuthResponse
import group.phorus.auth.commons.bdd.app.dtos.LoginData
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.dtos.AccessToken
import group.phorus.test.commons.bdd.BaseRequestScenarioScope
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import org.junit.jupiter.api.Assertions.assertNotNull
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody


class AuthStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val requestScenarioScope: BaseRequestScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val userRepository: UserRepository,
) {
    @Given("the caller has the given login information:")
    fun `the caller has the given login information`(data: DataTable) {
        val loginData = data.asMaps().first().let {
            LoginData(
                email = it["email"],
                password = it["password"],
                device = it["device"],
                expires = it["expires"].toBoolean(),
            )
        }

        requestScenarioScope.request = loginData
    }


    @Then("the service returns the AuthResponse")
    fun `the service returns the AuthResponse`() {
        val response = responseScenarioScope.responseSpec!!
            .expectBody<AuthResponse>().returnResult().responseBody!!

        assertNotNull(response)

        baseScenarioScope.objects["loginResponse"] = response
        baseScenarioScope.objects["accessToken"] = response.accessToken.token
        baseScenarioScope.objects["refreshToken"] = response.refreshToken
    }

    @Then("the service returns the AccessToken")
    fun `the service returns the AccessToken`() {
        val response = responseScenarioScope.responseSpec!!
            .expectBody<AccessToken>().returnResult().responseBody!!

        assertNotNull(response)

        baseScenarioScope.objects["accessToken"] = response.token
    }
}