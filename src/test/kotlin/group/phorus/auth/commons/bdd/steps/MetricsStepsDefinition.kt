package group.phorus.auth.commons.bdd.steps

import io.cucumber.java.en.Then
import io.micrometer.core.instrument.MeterRegistry
import org.junit.jupiter.api.Assertions.assertNotNull
import org.springframework.beans.factory.annotation.Autowired

class MetricsStepsDefinition(
    @Autowired private val meterRegistry: MeterRegistry,
) {

    @Then("the timer {string} is recorded with mode {string} and exception {string}")
    fun `the auth timer is recorded`(metricName: String, mode: String, exception: String) {
        val timer = meterRegistry.find(metricName)
            .tag("mode", mode)
            .tag("exception", exception)
            .timer()

        assertNotNull(timer, "Expected timer '$metricName' with tags mode=$mode, exception=$exception to be recorded")
    }
}
