package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.model.Device
import group.phorus.auth.commons.bdd.app.repositories.DeviceRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.TokenFactory
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.java.en.Given
import kotlinx.coroutines.runBlocking
import org.springframework.beans.factory.annotation.Autowired
import java.util.*

class ValidatorStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val tokenFactory: TokenFactory,
    @Autowired private val authenticator: Authenticator,
    @Autowired private val deviceRepository: DeviceRepository,
    @Autowired private val userRepository: UserRepository,
) {
    @Given("the caller has a token for that user with privileges {string} and claim {string} = {string}")
    fun `the caller has a token for that user with custom claim`(privileges: String, claimName: String, claimValue: String) {
        val userId = baseScenarioScope.objects["userId"] as String
        val privilegesList = privileges.split(" ").filter { it.isNotBlank() }

        val accessToken = runBlocking {
            tokenFactory.createAccessToken(
                UUID.fromString(userId),
                privilegesList,
                mapOf(claimName to claimValue),
            )
        }

        // Extract JTI and create device entry so DeviceValidator passes
        val authData = authenticator.authenticate(accessToken.token, enableValidators = false)
        val user = userRepository.findById(UUID.fromString(userId)).get()

        deviceRepository.save(Device(
            name = "validator-device-${UUID.randomUUID()}",
            user = user,
            accessTokenJTI = authData.jti,
            refreshTokenJTI = "not-used",
            disabled = false
        ))

        baseScenarioScope.objects["accessToken"] = accessToken.token
    }
}
