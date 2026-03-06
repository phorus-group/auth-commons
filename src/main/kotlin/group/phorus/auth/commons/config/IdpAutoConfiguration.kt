package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.web.reactive.function.client.WebClient

@AutoConfiguration
class IdpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(WebClient::class)
    @ConditionalOnProperty(
        prefix = "group.phorus.security",
        name = ["idp.jwk-set-uri"],
    )
    fun webClient(builder: WebClient.Builder): WebClient =
        builder.build()
}
