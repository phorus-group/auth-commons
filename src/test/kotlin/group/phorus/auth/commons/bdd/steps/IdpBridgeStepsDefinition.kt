package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.controllers.BridgeResponse
import group.phorus.auth.commons.config.AuthMode
import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.java.After
import io.cucumber.java.Before
import io.cucumber.java.en.Then
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody

class IdpBridgeStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val securityConfiguration: SecurityConfiguration,
) {

    @Before("@idp-bridge")
    fun switchToIdpBridgeMode() {
        securityConfiguration.mode = AuthMode.IDP_BRIDGE
    }

    @After("@idp-bridge")
    fun resetToStandaloneMode() {
        securityConfiguration.mode = AuthMode.STANDALONE
    }

    @Then("the response contains a self-issued access token")
    fun `the response contains a self-issued access token`() {
        val response = responseScenarioScope.responseSpec!!
            .expectBody<BridgeResponse>().returnResult().responseBody!!

        assertNotNull(response.accessToken)
        assertNotNull(response.accessToken.token)
        assertTrue(response.accessToken.token.isNotBlank())

        baseScenarioScope.objects["accessToken"] = response.accessToken.token
    }
}
