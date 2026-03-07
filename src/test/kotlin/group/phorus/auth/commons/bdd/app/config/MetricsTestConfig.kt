package group.phorus.auth.commons.bdd.app.config

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class MetricsTestConfig {
    @Bean
    fun meterRegistry(): MeterRegistry = SimpleMeterRegistry()
}
