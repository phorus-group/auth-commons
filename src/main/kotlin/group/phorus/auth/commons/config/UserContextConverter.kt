package group.phorus.auth.commons.config

import group.phorus.auth.commons.dtos.AuthContextData
import group.phorus.auth.commons.services.Authenticator
import group.phorus.exception.handling.Unauthorized
import group.phorus.mapper.mapping.extensions.mapTo
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.core.convert.converter.Converter

@AutoConfiguration
class UserContextConverter(
    private val authenticator: Authenticator,
) : Converter<String, AuthContextData> {
    private val headerPrefix = "Bearer "

    override fun convert(authorization: String): AuthContextData {
        if (authorization.length <= headerPrefix.length) throw Unauthorized("Invalid authorization header size")
        if (!authorization.contains(headerPrefix)) throw Unauthorized("Bearer token not found")

        val jwt = authorization.substring(headerPrefix.length)

        return authenticator.authenticate(jwt, false).mapTo<AuthContextData>()!!
    }
}