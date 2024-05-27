package group.phorus.auth.commons.bdd.app.services

import group.phorus.auth.commons.bdd.app.dtos.AuthResponse
import group.phorus.auth.commons.bdd.app.dtos.LoginData
import group.phorus.auth.commons.dtos.AccessToken

interface AuthService {
    suspend fun login(loginData: LoginData): AuthResponse
    suspend fun refreshAccessToken(refreshToken: String): AccessToken
}
