package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.dtos.AccessToken
import group.phorus.auth.commons.dtos.TokenType
import group.phorus.auth.commons.services.TokenFactory
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.KeyAlgorithm
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*

@AutoConfiguration
@Service
class TokenFactoryImpl(
    private val securityConfiguration: SecurityConfiguration,
) : TokenFactory {
    init {
        if (securityConfiguration.jwt.encryption.encodedPublicKey == null)
            throw Exception("group.phorus.security.jwt.encryption.encodedPublicKey - Encoded public key not set")

        if (!Security.getAlgorithms("KeyFactory").contains(securityConfiguration.jwt.encryption?.algorithm))
            throw Exception("group.phorus.security.jwt.encryption.algorithm - Algorithm not found in the algorithms list, available: ${Security.getAlgorithms("KeyFactory")}")

        if (!Jwts.KEY.get().contains(securityConfiguration.jwt.encryption.keyAlgorithm))
            throw Exception("group.phorus.security.jwt.encryption.keyAlgorithm - Key algorithm not found in the Jwts key algorithms list, available: ${Jwts.KEY.get().keys}")

        if (!Jwts.ENC.get().contains(securityConfiguration.jwt.encryption.aeadAlgorithm))
            throw Exception("group.phorus.security.jwt.encryption.aeadAlgorithm - AEAD algorithm not found in the Jwts AEAD algorithms list, available: ${Jwts.ENC.get().keys}")
    }

    @Suppress("UNCHECKED_CAST")
    override suspend fun createAccessToken(userId: UUID, privileges: List<String>, properties: Map<String, String>): AccessToken {
        val currentTime = Instant.now()

        val keyBytes = Base64.getDecoder().decode(securityConfiguration.jwt.encryption.encodedPublicKey)
        val keyFactory = KeyFactory.getInstance(securityConfiguration.jwt.encryption.algorithm)
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))

        val token = Jwts.builder()
            .header()
                .add(ExtraClaims.TYPE, TokenType.ACCESS_TOKEN.name)
            .and()
            .claims()
                .id(UUID.nameUUIDFromBytes("${TokenType.ACCESS_TOKEN.name}-${userId}-${currentTime.toEpochMilli()}"
                    .toByteArray(StandardCharsets.UTF_8)).toString())
                .subject(userId.toString())
                .issuer(securityConfiguration.jwt.issuer)
                .issuedAt(Date.from(currentTime))
                .expiration(Date.from(currentTime.plusSeconds(securityConfiguration.jwt.expiration.tokenMinutes * 60)))
                .add("scope", privileges.joinToString(" "))
                .apply {
                    properties.forEach { (key, value) ->
                        add(key, value)
                    }
                }
            .and()
            .encryptWith(
                publicKey,
                Jwts.KEY.get().forKey(securityConfiguration.jwt.encryption.keyAlgorithm) as KeyAlgorithm<PublicKey, PrivateKey>,
                Jwts.ENC.get().forKey(securityConfiguration.jwt.encryption.aeadAlgorithm),
            )
            .compact()

        return AccessToken(
            token = token,
            privileges = privileges
        )
    }

    override suspend fun createRefreshToken(userId: UUID, expires: Boolean, properties: Map<String, String>): String {
        val currentTime = LocalDateTime.now().toInstant(ZoneOffset.UTC)

        val keyBytes = Base64.getDecoder().decode(securityConfiguration.jwt.encryption.encodedPublicKey)
        val keyFactory = KeyFactory.getInstance(securityConfiguration.jwt.encryption.algorithm)
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))

        return Jwts.builder()
            .header()
                .add(ExtraClaims.TYPE, TokenType.REFRESH_TOKEN.name)
            .and()
            .claims()
                .id(UUID.nameUUIDFromBytes("${TokenType.REFRESH_TOKEN.name}-${userId}-${currentTime.toEpochMilli()}"
                    .toByteArray(StandardCharsets.UTF_8)).toString())
                .subject(userId.toString())
                .issuer(securityConfiguration.jwt.issuer)
                .issuedAt(Date.from(currentTime))
                .apply {
                    if (expires) expiration(
                        currentTime.plusSeconds(securityConfiguration.jwt.expiration.refreshTokenMinutes * 60)
                            .let { Date.from(it) }
                    )

                    properties.forEach { (key, value) ->
                        add(key, value)
                    }
                }
            .and()
            .encryptWith(publicKey, Jwts.KEY.ECDH_ES_A256KW, Jwts.ENC.A256CBC_HS512)
            .compact()
    }
}