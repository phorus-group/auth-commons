package group.phorus.auth.commons.context

import group.phorus.auth.commons.dtos.ApiKeyContextData

/**
 * Coroutine context element that holds the authenticated API key identity for the current request.
 *
 * Populated by [group.phorus.auth.commons.filters.ApiKeyFilter] when API key authentication
 * succeeds. Access the current value via `ApiKeyContext.context.get()` anywhere in the
 * request handling coroutine.
 *
 * ```kotlin
 * val apiKey = ApiKeyContext.context.get()
 * println("Request from: ${apiKey.keyId}")
 * ```
 *
 * @see ApiKeyContextData
 * @see group.phorus.auth.commons.filters.ApiKeyFilter
 */
object ApiKeyContext {
    val context: ThreadLocal<ApiKeyContextData> = ThreadLocal()
}
