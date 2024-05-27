package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.dtos.AuthData
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.Authenticator
import group.phorus.auth.commons.services.Validator
import group.phorus.exception.handling.Unauthorized
import io.jsonwebtoken.*
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.stereotype.Service
import java.security.KeyFactory
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

@AutoConfiguration
@Service
class AuthenticatorImpl(
    private val securityConfiguration: SecurityConfiguration,
    private val validators: List<Validator>,
) : Authenticator {
    init {
        if (securityConfiguration.jwt.encryption.encodedPrivateKey == null)
            throw Exception("group.phorus.security.jwt.encryption.encodedPrivateKey - Encoded private key not set")

        if (!Security.getAlgorithms("KeyFactory").contains(securityConfiguration.jwt.encryption.algorithm))
            throw Exception("group.phorus.security.jwt.encryption.algorithm - Algorithm not found in the algorithms list, available: ${Security.getAlgorithms("KeyFactory")}")

        if (!Jwts.KEY.get().contains(securityConfiguration.jwt.encryption.keyAlgorithm))
            throw Exception("group.phorus.security.jwt.encryption.keyAlgorithm - Key algorithm not found in the Jwts key algorithms list, available: ${Jwts.KEY.get().keys}")

        if (!Jwts.ENC.get().contains(securityConfiguration.jwt.encryption.aeadAlgorithm))
            throw Exception("group.phorus.security.jwt.encryption.aeadAlgorithm - AEAD algorithm not found in the Jwts AEAD algorithms list, available: ${Jwts.ENC.get().keys}")
    }

    override fun authenticate(jwt: String, enableValidators: Boolean): AuthData {
        val enabledValidators = if (enableValidators) validators else emptyList()

        val claims = parseClaims(jwt)
        val tokenType = claims.header[ExtraClaims.TYPE]?.let { TokenType.valueOf(it.toString()) }
            ?: throw Unauthorized("Authentication failed, please log in again")

        val jti = claims.payload.id
        val userId = claims.payload.subject.let { UUID.fromString(it) }
        val privileges: List<String> = claims.payload.get("scope", String::class.java)
            ?.split(" ") ?: emptyList()

        val properties = claims.payload.map { (key, value) ->
            key to value.toString()
        }.toMap().also { props ->
            props.forEach { (key, value) ->
                enabledValidators.filter { it.accepts(key) }.forEach { validator ->
                    if (!validator.isValid(value, props))
                        throw Unauthorized("Authentication failed, please log in again")
                }
            }
        }.filter { it.key != Claims.ID && it.key != Claims.SUBJECT && it.key !=  "scope"}

        return AuthData(
            userId = userId,
            tokenType = tokenType,
            jti = jti,
            privileges = privileges,
            properties = properties,
        )
    }

    override fun parseClaims(jwt: String): Jwe<Claims> =
        runCatching {
            val keyBytes = Base64.getDecoder().decode(securityConfiguration.jwt.encryption.encodedPrivateKey)
            val keyFactory = KeyFactory.getInstance(securityConfiguration.jwt.encryption.algorithm)
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))

            Jwts.parser().decryptWith(privateKey).build().parseEncryptedClaims(jwt)
        }.getOrElse {
            when(it) {
                is SecurityException,
                is IllegalArgumentException,
                is MalformedJwtException,
                is UnsupportedJwtException -> throw Unauthorized("Invalid JWT Token")
                is ExpiredJwtException -> throw Unauthorized("JWT Token expired")
                else -> throw Unauthorized("Unknown exception related to the JWT Token: ${it.message}")
            }
        }
}

interface ExtraClaims {
    companion object {
        const val TYPE = "type"
    }
}