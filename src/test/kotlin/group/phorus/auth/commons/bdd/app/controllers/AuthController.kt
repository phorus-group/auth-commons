package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.bdd.app.dtos.AuthResponse
import group.phorus.auth.commons.bdd.app.dtos.LoginData
import group.phorus.auth.commons.bdd.app.services.AuthService
import group.phorus.auth.commons.dtos.AccessToken
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authService: AuthService,
) {
    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    suspend fun login(
        @RequestBody
        loginData: LoginData,
    ): AuthResponse = authService.login(loginData)

    @GetMapping("/token")
    @ResponseStatus(HttpStatus.OK)
    suspend fun refreshToken(
        @RequestHeader(name = "Authorization")
        authToken: String,
    ): AccessToken = authService.refreshAccessToken(authToken)
}