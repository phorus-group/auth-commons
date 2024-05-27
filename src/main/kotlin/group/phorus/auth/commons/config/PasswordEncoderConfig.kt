package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

@AutoConfiguration
class PasswordEncoderConfig {

    @Bean
    fun passwordEncoder(): SCryptPasswordEncoder =
        SCryptPasswordEncoder(65536, 8, 1, 32, 16)
}
