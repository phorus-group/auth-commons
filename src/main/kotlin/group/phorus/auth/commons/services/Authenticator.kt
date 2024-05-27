package group.phorus.auth.commons.services

import group.phorus.auth.commons.dtos.AuthData
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwe

interface Authenticator {
    fun authenticate(jwt: String, enableValidators: Boolean = true): AuthData
    fun parseClaims(jwt: String): Jwe<Claims>
}