package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

@AutoConfiguration
@ConfigurationProperties(prefix = "group.phorus.security")
class SecurityConfiguration(
    var enableFilter: Boolean? = null,
    var refreshTokenPath: String? = null,
    var ignoredPaths: List<Path> = emptyList(),

    @NestedConfigurationProperty
    var jwt: JwtConfiguration = JwtConfiguration(),
)

class Path (
    var path: String,
    var method: String? = null,
)

class JwtConfiguration(
    var issuer: String? = null,

    @NestedConfigurationProperty
    var encryption: JwtEncryptionConfiguration = JwtEncryptionConfiguration(),

    @NestedConfigurationProperty
    var expiration: JwtExpirationConfiguration = JwtExpirationConfiguration(),
)

class JwtExpirationConfiguration(
    var tokenMinutes: Long = 10,
    var refreshTokenMinutes: Long = 1440,
)

class JwtEncryptionConfiguration(
    var algorithm: String = "EC",
    var keyAlgorithm: String = "ECDH-ES+A256KW",
    var aeadAlgorithm: String = "A192CBC-HS384",
    var encodedPublicKey: String? = null,
    var encodedPrivateKey: String? = null,
)
