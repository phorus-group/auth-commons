package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

@AutoConfiguration
class PasswordEncoderConfig(
    private val securityConfiguration: SecurityConfiguration,
) {

    @Bean
    fun passwordEncoder(): SCryptPasswordEncoder =
        with(securityConfiguration.passwordEncoder) {
            SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength)
        }
}
