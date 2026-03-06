package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.bdd.app.model.Device
import group.phorus.auth.commons.bdd.app.model.User
import group.phorus.auth.commons.bdd.app.repositories.DeviceRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.dtos.AccessToken
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.TokenFactory
import group.phorus.auth.commons.services.impl.IdpAuthenticator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/bridge")
class BridgeController(
    private val idpAuthenticator: IdpAuthenticator?,
    private val tokenFactory: TokenFactory,
    private val authenticator: Authenticator,
    private val userRepository: UserRepository,
    private val deviceRepository: DeviceRepository,
) {
    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    suspend fun bridgeLogin(
        @RequestHeader(name = "Authorization") authHeader: String,
    ): BridgeResponse {
        val idpToken = authHeader.removePrefix("Bearer ")
        val idpAuth = idpAuthenticator
            ?: throw IllegalStateException("IdpAuthenticator is not configured for IDP_BRIDGE mode")

        val authData = idpAuth.authenticate(idpToken)

        // Provision a local user for the IdP subject
        val user = withContext(Dispatchers.IO) {
            userRepository.findByEmail("bridge-${authData.userId}@idp.example.com").orElseGet {
                userRepository.saveAndFlush(
                    User(
                        name = "bridge-user",
                        email = "bridge-${authData.userId}@idp.example.com",
                        passwordHash = "not-used",
                    )
                )
            }
        }

        // This is just a placeholder for custom properties
        val properties = mapOf("tokenThingy" to true.toString())

        val accessToken = tokenFactory.createAccessToken(
            user.id!!,
            authData.privileges,
            properties,
        )

        // Extract JTI and create a device entry so test validators pass
        val accessTokenJTI = authenticator.authenticate(accessToken.token, enableValidators = false).jti

        withContext(Dispatchers.IO) {
            deviceRepository.saveAndFlush(
                Device(
                    name = "bridge-device",
                    user = user,
                    accessTokenJTI = accessTokenJTI,
                    refreshTokenJTI = accessTokenJTI,
                )
            )
        }

        return BridgeResponse(accessToken = accessToken)
    }
}

data class BridgeResponse(
    val accessToken: AccessToken,
)
