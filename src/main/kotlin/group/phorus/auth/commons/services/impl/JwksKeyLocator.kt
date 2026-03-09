package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.config.SecurityConfiguration
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.LocatorAdapter
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.security.Key
import java.security.PublicKey
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * A JJWT [LocatorAdapter] that resolves JWS verification keys by fetching the
 * [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) from
 * an external Identity Provider's endpoint.
 *
 * ### Key resolution strategy
 * 1. Look up the `kid` (Key ID) from the JWS header in the local cache.
 * 2. If the key is **not** found and the cache has not been refreshed within the last
 *    cooldown period (30 seconds), fetch fresh keys from the JWKS endpoint.
 * 3. If the key is **still** not found after a refresh, throw an exception.
 *
 * ### Caching
 * - Keys are cached in memory with a configurable TTL
 *   ([`idp.jwks-cache-ttl-minutes`][group.phorus.auth.commons.config.IdpConfiguration.jwksCacheTtlMinutes]).
 * - The cache is **eagerly refreshed** on the first request after TTL expiry.
 * - A **cooldown** prevents excessive fetches when an unknown `kid` is presented repeatedly.
 *
 * ### Thread safety
 * All cache operations are protected by a [ReentrantReadWriteLock].
 *
 * ### Compatibility
 * Works with all major IdPs that expose a JWKS endpoint:
 * - **Auth0**: `https://{tenant}.auth0.com/.well-known/jwks.json`
 * - **Azure AD / Entra ID**: `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`
 * - **Google / Firebase**: `https://www.googleapis.com/oauth2/v3/certs`
 * - **Keycloak**: `https://{host}/realms/{realm}/protocol/openid-connect/certs`
 * - **Okta**: `https://{domain}/oauth2/{serverId}/v1/keys`
 *
 * @see group.phorus.auth.commons.config.IdpConfiguration
 */
@AutoConfiguration
@Service
@ConditionalOnProperty(
    prefix = "group.phorus.security",
    name = ["idp.jwk-set-uri"],
)
class JwksKeyLocator(
    private val securityConfiguration: SecurityConfiguration,
    private val webClient: WebClient,
) : LocatorAdapter<Key>() {

    private val log = LoggerFactory.getLogger(JwksKeyLocator::class.java)

    /** kid -> PublicKey cache. */
    private val keyCache = ConcurrentHashMap<String, PublicKey>()

    /** Timestamp of the last successful JWKS fetch. */
    @Volatile
    private var lastFetchTime: Instant = Instant.EPOCH

    /** Read/write lock protecting cache refresh operations. */
    private val lock = ReentrantReadWriteLock()

    private val cacheTtl = Duration.ofMinutes(securityConfiguration.idp.jwksCacheTtlMinutes)

    /**
     * Minimum interval between consecutive JWKS fetches to prevent abuse.
     * Even if an unknown `kid` is presented, we won't re-fetch more often than this.
     */
    private val refreshCooldown = Duration.ofSeconds(30)

    /**
     * Resolves the [PublicKey] for verifying a JWS token based on its `kid` header parameter.
     *
     * @param header The JWS header containing the `kid` (Key ID) parameter.
     * @return The [PublicKey] to use for signature verification.
     * @throws SecurityException if the `kid` is missing or no matching key is found.
     */
    override fun locate(header: JwsHeader): Key {
        val kid = header.keyId
            ?: throw SecurityException("JWS token is missing the 'kid' (Key ID) header parameter")

        // Try cache first (fast path, read lock only)
        lock.read {
            keyCache[kid]?.let { return it }
        }

        // Cache miss, refresh if allowed
        refreshKeysIfNeeded()

        // Retry after refresh
        return lock.read {
            keyCache[kid]
                ?: throw SecurityException(
                    "No key found for kid '$kid' in JWKS from ${securityConfiguration.idp.jwkSetUri}. " +
                    "Available kids: ${keyCache.keys}"
                )
        }
    }

    /**
     * Forces a cache refresh, regardless of TTL.
     * Useful for testing or manual key rotation handling.
     */
    fun forceRefresh() {
        lock.write {
            fetchAndCacheKeys()
        }
    }

    /**
     * Refreshes the JWKS cache if the TTL has expired.
     * The cooldown acts as a minimum TTL to prevent abuse even if configured TTL is very low.
     */
    private fun refreshKeysIfNeeded() {
        val now = Instant.now()
        val minRefreshInterval = maxOf(cacheTtl, refreshCooldown)

        // Quick check without lock (optimization)
        if (Duration.between(lastFetchTime, now) < minRefreshInterval) {
            return
        }

        lock.write {
            // Double-check: another thread may have refreshed while we waited for the write lock
            val timeSinceLastFetch = Duration.between(lastFetchTime, now)
            if (timeSinceLastFetch < minRefreshInterval) {
                return
            }

            fetchAndCacheKeys()
        }
    }

    /**
     * Fetches the JWKS from the IdP endpoint and populates the cache.
     * Must be called while holding the write lock.
     */
    private fun fetchAndCacheKeys() {
        val jwkSetUri = securityConfiguration.idp.jwkSetUri
            ?: throw IllegalStateException(
                "group.phorus.security.idp.jwk-set-uri must be configured for IdP modes"
            )

        log.debug("Fetching JWKS from {}", jwkSetUri)

        val jwksJson = runCatching {
            webClient.get()
                .uri(jwkSetUri)
                .retrieve()
                .bodyToMono<String>()
                .toFuture()
                .get(10, TimeUnit.SECONDS)
                ?: throw IllegalStateException("Empty response from JWKS endpoint: $jwkSetUri")
        }.getOrElse { ex ->
            log.error("Failed to fetch JWKS from {}: {}", jwkSetUri, ex.message)
            throw SecurityException("Failed to fetch JWKS from $jwkSetUri: ${ex.message}", ex)
        }

        val jwkSet = runCatching {
            Jwks.setParser().build().parse(jwksJson)
        }.getOrElse { ex ->
            log.error("Failed to parse JWKS from {}: {}", jwkSetUri, ex.message)
            throw SecurityException("Failed to parse JWKS from $jwkSetUri: ${ex.message}", ex)
        }

        val newKeys = ConcurrentHashMap<String, PublicKey>()
        // JwkSet extends both MutableMap and MutableIterable<Jwk<*>>,
        // so we cast to Iterable to resolve the iterator() ambiguity.
        for (jwk in (jwkSet as Iterable<Jwk<*>>)) {
            val kid = jwk.id ?: continue
            val key = jwk.toKey()
            if (key is PublicKey) {
                newKeys[kid] = key
            }
        }

        log.debug("Fetched {} public keys from JWKS: kids={}", newKeys.size, newKeys.keys)

        keyCache.clear()
        keyCache.putAll(newKeys)
        lastFetchTime = Instant.now()
    }
}
