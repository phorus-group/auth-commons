package group.phorus.auth.commons.authorization.handler.rest

import group.phorus.auth.commons.authorization.Handler

/**
 * HTTP methods for REST handlers.
 */
enum class HTTPMethod {
    POST, GET, PUT, DELETE
}

/**
 * REST handler configuration for making HTTP API calls during authorization.
 *
 * ## Examples
 * ```kotlin
 * RESTHandler(
 *   call = "/api/permissions/\${auth::userId}",
 *   saveTo = "permissions",
 * )
 * ```
 *
 * @param call The URL endpoint to call. Supports template variables for dynamic URLs.
 * @param method The HTTP method to use for the request.
 * @param forwardAuth Whether to forward the Authorization header from the current request.
 * @param saveTo The temporary context key under which to store the response.
 */
@Target(allowedTargets = [])
annotation class RESTHandler(
    val call: String = "",
    val method: HTTPMethod = HTTPMethod.GET,
    val forwardAuth: Boolean = true,
    val saveTo: String = "handler"
)