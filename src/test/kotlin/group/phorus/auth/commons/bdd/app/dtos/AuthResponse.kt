package group.phorus.auth.commons.bdd.app.dtos

import group.phorus.auth.commons.dtos.AccessToken

data class AuthResponse(
    var accessToken: AccessToken,
    var refreshToken: String,
)
