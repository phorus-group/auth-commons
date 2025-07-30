package group.phorus.auth.commons.authorization

/**
 * Enum defining how multiple [Authorize] definitions within a single [Authorization] should be evaluated.
 */
enum class AuthorizationMode {
    /**
     * OR mode: Any one of the [Authorize] definitions needs to pass for the [Authorization] to be valid.
     * This is the default and most common mode. Definitions are evaluated in order of declaration,
     * and evaluation stops as soon as one definition grants access.
     *
     * **Performance Tip**: Place lightweight checks before expensive ones (e.g., privilege checks
     * before external handler calls) to optimize performance.
     *
     * Example:
     * ```kotlin
     * @Authorization(
     *     mode = AuthorizationMode.OR,
     *     definitions = [
     *         Authorize(matches = ["auth::privileges/admin"]),           // Fast privilege check first
     *         Authorize(value = "::ownerId", matches = ["auth::userId"]),    // Medium speed property check
     *         Authorize(                                                     // Expensive handler call last
     *             restHandler = RESTHandler(call = "/api/delegations/\${::id}"),
     *             value = "response::delegateId",
     *             matches = ["auth::userId"]
     *         )
     *     ]
     * )
     * ```
     * User gets access if they are admin OR owner OR have delegation (checked in that order).
     */
    OR,

    /**
     * AND mode: All of the [Authorize] definitions must pass for the [Authorization] to be valid.
     * Use this when you need multiple conditions to be satisfied simultaneously. Definitions are
     * evaluated in order of declaration, and evaluation stops as soon as one definition fails.
     *
     * **Performance Tip**: Place fastest/cheapest checks first to fail fast on unauthorized access.
     * Place expensive checks (like external handler calls) last since they will only be evaluated
     * if all previous checks pass.
     *
     * Example:
     * ```kotlin
     * @Authorization(
     *     mode = AuthorizationMode.AND,
     *     definitions = [
     *         Authorize(matches = ["auth::privileges/finance:read"]),        // Fast privilege check first
     *         Authorize(value = "::departmentId", matches = ["auth::departmentId"]), // Medium property check
     *         Authorize(                                                     // Expensive handler call last
     *             restHandler = RESTHandler(call = "/api/approvals/financial/\${::id}"),
     *             value = "response::isApproved",
     *             matches = ["true"]
     *         )
     *     ]
     * )
     * ```
     * User gets access only if they have finance privileges AND are in the right department AND have approval.
     */
    AND
}

/**
 * Enum with common data operations.
 */
enum class Operation {
    CREATE, READ, UPDATE, DELETE, ALL
}

/**
 * Annotation used to check if client has authorization to access a specific entity, or entity field.
 * This annotation can be used multiple times in the same entity or field to specify multiple ways of
 * validating the client's authorization.
 *
 * ## Evaluation Logic
 *
 * ### Multiple Authorization Annotations
 * When multiple `@Authorization` annotations are present on the same class/field, they are evaluated with OR logic:
 * - If ANY one `@Authorization` annotation grants access, the caller gets access
 * - Annotations are evaluated in priority order (higher priority first), then by code order (top to bottom)
 * - Evaluation stops as soon as one annotation grants access
 *
 * ### Within a Single Authorization Annotation
 * The [mode] parameter controls how multiple [definitions] within a single annotation are evaluated:
 * - `OR` mode (default): ANY one definition needs to pass (evaluated in order, stops at first success)
 * - `AND` mode: ALL definitions must pass (evaluated in order, stops at first failure)
 *
 * ### Within a Single Authorize Definition
 * Multiple [matches][Authorize.matches] within a single [Authorize] are always evaluated with OR logic
 * in order.
 *
 * ### Performance Optimization Guidelines
 *
 * **For OR mode definitions**: Place lightweight checks before expensive ones
 * ```kotlin
 * @Authorization(definitions = [
 *     Authorize(matches = ["auth::privileges/admin"]),               // Fastest: privilege check
 *     Authorize(value = "::ownerId", matches = ["auth::userId"]),    // Medium: property comparison
 *     Authorize(restHandler = RESTHandler(call = "/api/..."))        // Slowest: external API call
 * ])
 * ```
 *
 * **For AND mode definitions**: Place fastest checks first to fail fast
 * ```kotlin
 * @Authorization(
 *     mode = AuthorizationMode.AND,
 *     definitions = [
 *         Authorize(matches = ["auth::privileges/required"]),        // Fast failure if no privilege
 *         Authorize(value = "::status", matches = ["active"]),       // Fast property check
 *         Authorize(restHandler = RESTHandler(call = "/api/..."))    // Expensive check only if others pass
 *     ]
 * )
 * ```
 *
 * ## Examples
 *
 * ### Example 1: Simple OR Logic (Default)
 * ```kotlin
 * @Authorization(definitions = [
 *     Authorize(value = "::ownerId", matches = ["auth::userId"]),   // Owner can access
 *     Authorize(matches = ["auth::privileges/admin"])               // OR admin can access
 * ])
 * var sensitiveData: String? = null
 * ```
 *
 * ### Example 2: AND Logic - Multiple Conditions Required
 * ```kotlin
 * @Authorization(
 *     mode = AuthorizationMode.AND,
 *     definitions = [
 *         Authorize(matches = ["auth::privileges/financial:read"]),              // Must have privilege
 *         Authorize(value = "httpRequest::remoteAddress", matches = ["10.0.*"]), // AND be on internal network
 *         Authorize(value = "httpRequest::method", matches = ["GET"])            // AND use the GET HTTP method
 *     ]
 * )
 * var financialData: String? = null
 * ```
 *
 * ### Example 3: Multiple Authorization Annotations with Priorities
 * ```kotlin
 * // High priority: Admin bypass (checked first)
 * @Authorization(
 *     priority = 100,
 *     definitions = [Authorize(matches = ["auth::privileges/admin"])]
 * )
 * // Medium priority: Departmental access (checked if admin check fails)
 * @Authorization(
 *     priority = 50,
 *     mode = AuthorizationMode.AND,
 *     definitions = [
 *         Authorize(matches = ["auth::privileges/department:access"]),
 *         Authorize(value = "::departmentId", matches = ["auth::departmentId"])
 *     ]
 * )
 * // Low priority: Owner access (checked last)
 * @Authorization(
 *     priority = 10,
 *     definitions = [Authorize(value = "::ownerId", matches = ["auth::userId"])]
 * )
 * var departmentData: String? = null
 * ```
 *
 * ### Example 4: Performance-Optimized Complex Authorization
 * ```kotlin
 * @Authorization(
 *     mode = AuthorizationMode.OR,
 *     definitions = [
 *         // Fast checks first (most common cases)
 *         Authorize(matches = ["auth::privileges/admin"]),
 *         Authorize(value = "::ownerId", matches = ["auth::userId"]),
 *
 *         // Expensive external validation last (uncommon case)
 *         Authorize(
 *             restHandler = RESTHandler(call = "/api/delegation-check/\${::id}/\${auth::userId}"),
 *             value = "response::hasAccess",
 *             matches = ["true"]
 *         )
 *     ]
 * )
 * var complexData: String? = null
 * ```
 *
 * @param mode How to evaluate multiple [definitions] within this annotation. Default is [AuthorizationMode.OR].
 * @param priority Priority for this authorization annotation. Higher values are checked first.
 *                 If multiple annotations have the same priority, they are evaluated in code order (top to bottom).
 *                 Default is 0.
 * @param operations The operations that will be covered by this [Authorization] definition. Default: [Operation.ALL].
 * @param definitions Definitions used to configure the way the client's authorization should be validated.
 *                   These are evaluated in order of declaration. For optimal performance, place lightweight
 *                   checks before expensive ones in OR mode, and place fast-failing checks first in AND mode.
 */
@Repeatable
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY_GETTER, AnnotationTarget.PROPERTY_SETTER, AnnotationTarget.FIELD,
    AnnotationTarget.PROPERTY)
annotation class Authorization(
    vararg val definitions: Authorize = [],
    val mode: AuthorizationMode = AuthorizationMode.OR,
    val priority: Int = 0,
    val operations: Array<Operation> = [Operation.ALL],
)