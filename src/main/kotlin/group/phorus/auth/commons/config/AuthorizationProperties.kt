package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

@AutoConfiguration
@ConfigurationProperties(prefix = "group.phorus.authorization")
class AuthorizationProperties(
    /**
     * Handler configuration for external data fetching.
     */
    @NestedConfigurationProperty
    var handler: HandlerProperties = HandlerProperties(),

    /**
     * Hibernate interceptor configuration.
     */
    @NestedConfigurationProperty
    var interceptor: InterceptorProperties = InterceptorProperties(),
)

/**
 * Configuration for authorization handlers.
 */
class HandlerProperties(
    /**
     * Timeout for handler execution in milliseconds.
     */
    var timeoutMs: Long = 5000,

    /**
     * Number of retry attempts for failed handler calls.
     */
    var retryAttempts: Int = 3,

    /**
     * Whether to cache handler responses.
     */
    var cacheEnabled: Boolean = true,

    /**
     * Cache TTL in seconds.
     */
    var cacheTtlSeconds: Long = 300,

    /**
     * Maximum cache size.
     */
    var maxCacheSize: Long = 1000
)

/**
 * Configuration for Hibernate interceptor.
 */
class InterceptorProperties(
    /**
     * Whether to enable the Hibernate interceptor. If disabled, the @Authorization annotation will stop working.
     */
    var enable: Boolean = true,
)