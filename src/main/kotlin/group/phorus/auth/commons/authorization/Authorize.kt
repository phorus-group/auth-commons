package group.phorus.auth.commons.authorization

import group.phorus.auth.commons.authorization.handler.rest.RESTHandler
import kotlin.reflect.KClass

/**
 * Base interface for custom authorization handlers.
 *
 * Implement this interface to create custom authorization handlers and handler processors that can be used
 * in the [Authorize.handler] property.
 *
 * Example:
 * ```kotlin
 * data class MyConfig(val someProperty: String) : Handler
 *
 * @Component
 * class MyCustomHandlerProcessor : AuthorizationHandlerProcessor<MyConfig> {
 *     override suspend fun execute(config: MyConfig, entity: Any?, handlerContexts: Map<String, Any>): Any? {
 *         // Custom authorization logic
 *         return result
 *     }
 * }
 * ```
 *
 * @param saveTo The temporary context key under which to store the response.
 */
interface Handler {
    val saveTo: String
}

/**
 * Empty handler implementation used as default value.
 * Indicates no custom handler will be used.
 */
object EmptyHandler : Handler {
    override val saveTo: String = ""
}

/**
 * Annotation used to configure the way the [Authorization] should be validated.
 * Made to be used alone or in conjunction with other [Authorize] annotations within an [Authorization].
 *
 * The [value], [matches], [handlerConfig], and [RESTHandler.call] fields support special context references with prefixes
 * separated by `::`, and string templates for dynamic values. These can use data from the current database entity, contexts,
 * custom contexts, and (from handlers) handler, response, and saveTo values. For example:
 * `value = "auth::privileges/organization-${::organizationId}::addresses:read"`.
 *
 * The available contexts depend on which context providers are registered, but common ones include:
 * - `auth`: Authentication context from [AuthContextData][group.phorus.auth.commons.dtos.AuthContextData] object
 *   containing userId, privileges, and properties. For example: `auth::privileges/users:all`, `auth::userId`.
 * - `httpRequest`: Authentication context from [HTTPContextData][group.phorus.auth.commons.dtos.HTTPContextData] object
 *   containing method, path, headers, IP address, etc.
 *   For example: `httpRequest::method`, `httpRequest::path`, `httpRequest::remoteAddress`.
 * - `response`: Context containing the response from the current handler execution. Available only when using handlers,
 *   and only within the same [Authorize] instance where the handler executed.
 *   For example: `response::permissions/admin`, `response::user/email`.
 * - `handler`: Default context for handler responses when no specific [saveTo][RESTHandler.saveTo] is specified.
 *   This contains the last handler response and persists for the entire [Authorization] annotation and all its
 *   [definitions][Authorization.definitions].
 *   For example: `handler::permissions/admin`, `handler::user/id`.
 * - Custom contexts: Any context specified by [saveTo][RESTHandler.saveTo] in handlers within the same [Authorization],
 *   or custom context providers implementing [AuthorizationContextProvider][group.phorus.auth.commons.authorization.context.AuthorizationContextProvider].
 *   For example: `permissions::admin`, `userInfo::profile/email`, `myCustomContext::someData`.
 * - Entity access: You can also access entity and subentity fields by using no context prefixes on the left side of the ::, like: `::user/id`
 *
 * ## Handler Usage Examples
 *
 * ### REST Handler
 * ```kotlin
 * // Basic REST handler
 * Authorize(
 *     restHandler = RESTHandler(call = "/api/permissions/\${auth::userId}"),
 *     matches = ["response::permissions/admin"], // Access will be granted if "admin" is present in the permissions collection
 * )
 *
 * // REST handler with custom context
 * Authorize(
 *     restHandler = RESTHandler(
 *         call = "/api/user/\${auth::userId}",
 *         method = HTTPMethod.GET,
 *         forwardAuth = true,
 *         saveTo = "userData"
 *     ),
 *     value = "userData::role",
 *     matches = ["admin", "manager"] // Access will be granted if role matches "admin" or "manager"
 * )
 *
 * ### Custom Handler
 * ```kotlin
 * data class DatabaseConfig(val userId: String, val resourceId: String) : Handler
 *
 * @Component
 * class DatabasePermissionHandlerProcessor : AuthorizationHandlerProcessor<DatabaseConfig> {
 *     override suspend fun execute(config: DatabaseConfig, entity: Any?, handlerContexts: Map<String, Any>): Any? {
 *         // Custom logic to query database
 *         return queryPermissions(config.userId, config.resourceId)
 *     }
 * }
 *
 * Authorize(
 *     handler = DatabaseConfig::class,
 *     handlerConfig = """{"userId": "${auth::userId}", "resourceId": "${::id}"}""",
 *     value = "response::hasAccess",
 *     matches = ["true"]
 * )
 * ```
 *
 * ### Handler Chaining
 * ```kotlin
 * @Authorization(definitions = [
 *     // First: Fetch user data
 *     Authorize(
 *         restHandler = RESTHandler(
 *             call = "/api/users/\${auth::userId}",
 *             saveTo = "userData"
 *         )
 *     ),
 *     // Second: Use user data in another handler call
 *     Authorize(
 *         restHandler = RESTHandler(
 *             call = "/api/permissions/\${userData::user/email}/entity/\${::id}"
 *         ),
 *         value = "response::canAccess",
 *         matches = ["true"]
 *     )
 * ])
 * ```
 *
 * ## Custom Context Providers
 *
 * You can create custom context providers by implementing [AuthorizationContextProvider][group.phorus.auth.commons.authorization.context.AuthorizationContextProvider]:
 * ```kotlin
 * @Component
 * class MyCustomContextProvider : AuthorizationContextProvider {
 *     override fun getContextPrefix(): String = "myCustom"
 *     override fun getContextObject(): Any? = getMyCustomData()
 *     override fun getPriority(): Int = 0
 * }
 * ```
 * Then use it in authorization rules: `myCustom::someProperty/nestedValue`
 *
 * @param value source field used to validate the user's [Authorization]. Can be used with contexts and nested
 *   property access (e.g., "user/id").
 * @param matches array containing one or more fields that should match the [value] field for this [Authorize] instance
 *  to be valid. If no [value] field is provided, the [Authorize] instance will be considered valid as long as
 *  the [matches] value exists, for example:
 *  ```kotlin
 *    Authorize(matches = ["auth::privileges/users:read"])
 *  ```
 *  If the privilege `privileges/users:read` exists inside the `auth` context, this [Authorize] instance will
 *  be considered valid.
 *
 *  The [Authorize] instance will be considered valid if at least one of the [matches] matches the [value] field.
 *  Multiple matches within a single [Authorize] are always evaluated with OR logic in priority order.
 *
 *  If no [matches] are provided, the [Authorize] instance won't be considered valid or invalid.
 *  If no [matches] are provided but a handler ([restHandler] or [handler]) is specified, the [Authorize]
 *  will execute the handler but perform no validation, effectively acting as a setup step for subsequent [Authorize] definitions.
 *
 * @param restHandler Built-in REST handler for making HTTP API calls. This is the most common handler type.
 *   The handler response is automatically saved to both the `response` context (current handler only) and
 *   the context specified by [RESTHandler.saveTo] (defaults to `handler`, persists across definitions).
 *
 *   **REST Handler Response Contexts:**
 *   - `response::` - Contains the current REST handler's response (works in the current [Authorize] definition only)
 *   - `handler::` - Default persistent context when no [saveTo][RESTHandler.saveTo] is specified (works in the current [Authorization])
 *   - `{saveTo}::` - Custom persistent context specified by [RESTHandler.saveTo] (works in the current [Authorization])
 *
 * @param handler Custom handler class for specialized authorization logic. Must implement the
 *   [Handler] interface. The corresponding [group.phorus.auth.commons.authorization.handler.AuthorizationHandlerProcessor] will process this handler.
 *   Use [handlerConfig] to pass configuration data to the custom handler in a JSON format.
 *   Cannot be used together with [restHandler], if you do the restHandler will take priority over the custom handler.
 *
 * @param handlerConfig JSON configuration string for custom handlers. This string will be parsed and passed
 *   to the custom handler specified by [handler]. Supports template variable substitution.
 *   Example: `"""{"userId": "${auth::userId}", "resourceId": "${::id}"}"""`
 *   Only used when [handler] is specified.
 */
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class Authorize(
    val value: String = "",
    val matches: Array<String> = [],
    val restHandler: RESTHandler = RESTHandler(),
    val handler: KClass<out Handler> = EmptyHandler::class,
    val handlerConfig: String = "",
)
