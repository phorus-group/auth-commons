package group.phorus.auth.commons.config

import group.phorus.metrics.commons.TagNames
import group.phorus.metrics.commons.timedSuspend
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty

/**
 * Autoconfigured bean that records authentication metrics using
 * [metrics-commons](https://github.com/phorus-group/metrics-commons).
 *
 * Only active when:
 * - A `io.micrometer.core.instrument.MeterRegistry` bean exists (e.g. via Spring Boot Actuator)
 * - The property `phorus.auth-commons.metrics.enabled` is `true` (default)
 *
 * ### Authentication timers
 *
 * Two timers are provided for monitoring authentication performance and failures:
 *
 * #### Token authentication duration timer
 * Produces a timer named `auth.jwt.token.authentication` with tags:
 * - `mode`: the authentication mode (`standalone`, `idp_bridge`, or `idp_delegated`)
 * - [TagNames.EXCEPTION]: `None` on success, or the exception class name on failure (e.g. `Unauthorized`, `ExpiredJwtException`)
 *
 * #### API key authentication duration timer
 * Produces a timer named `auth.api.key.authentication` with tags:
 * - [TagNames.EXCEPTION]: `None` on success, or the exception class name on failure
 *
 * Both timers provide:
 * - **Performance monitoring**: p50/p95/p99 latencies to detect slow authentication
 * - **Success rate**: ratio of exception=None to failures
 * - **Failure breakdown**: which exception types are most common (security monitoring)
 *
 * Consuming projects can disable metrics by setting:
 * ```yaml
 * phorus:
 *   auth-commons:
 *     metrics:
 *       enabled: false
 * ```
 */
@AutoConfiguration
@ConditionalOnBean(MeterRegistry::class)
@ConditionalOnProperty(
    prefix = "phorus.auth-commons.metrics",
    name = ["enabled"],
    matchIfMissing = true,
)
class MetricsRecorder(
    private val meterRegistry: MeterRegistry,
) {

    /**
     * Times an authentication operation and records duration + success/failure.
     *
     * The timer automatically tags exceptions via [timedSuspend], so you get both
     * performance data and failure breakdown in a single metric.
     *
     * @param mode the authentication mode (e.g. `standalone`, `idp_bridge`, `idp_delegated`).
     * @param block the authentication operation to time.
     * @return the result of the authentication operation.
     * @throws Exception any exception from [block], after recording its duration and type.
     */
    suspend fun <T> timeAuthentication(mode: String, block: suspend () -> T): T =
        meterRegistry.timedSuspend(
            name = "auth.jwt.token.authentication",
            "mode" to mode,
            block = block,
        )

    /**
     * Times an API key authentication operation and records duration + success/failure.
     *
     * Produces a timer named `auth.api.key.authentication` with tags:
     * - [TagNames.EXCEPTION]: `None` on success, or the exception class name on failure
     *
     * This timer provides:
     * - **Performance monitoring**: p50/p95/p99 latencies to detect slow API key validation
     * - **Success rate**: ratio of exception=None to failures
     * - **Failure breakdown**: which exception types are most common (security monitoring)
     *
     * @param block the API key validation operation to time.
     * @return the result of the validation operation.
     * @throws Exception any exception from [block], after recording its duration and type.
     */
    suspend fun <T> timeApiKeyAuthentication(block: suspend () -> T): T =
        meterRegistry.timedSuspend(
            name = "auth.api.key.authentication",
            block = block,
        )
}
