package group.phorus.auth.commons.authorization

/**
 * Annotation used to configure the way the [Authorization] should be validated.
 * Made to be used alone or in conjunction with other [Authorize] annotations.
 *
 * Some parameters used by this annotation may have special prefixes referring to special contexts. These prefixes
 * must be used before any other value, and need to be separated from other values using `::`.
 * The available contexts are:
 * - `auth`: Context that uses the [AuthContextData][group.phorus.auth.commons.dtos.AuthContextData] object and
 *   contains the userId, privileges, and properties of the caller. For example: `auth::privileges/users:all`.
 * - `handler`: Context used to access the properties saved by the [set][Handler.set] property of the
 *   current [handler]. This context won't have anything if no handler has been set, or if the handler returned
 *   an invalid response. For example: `handler::user/userId`.
 *
 * Remember also that all string fields, except [value], are compatible with string templates, and these
 * templates allow you to insert the same values used for the [value] field, so you can use values
 * like: `auth::privileges/organization-${handler::memberships/organization/id}::addresses:read`.
 * If you use string templates with any kind of arrays, the field using the string template will be used internally
 * multiple times with each item of the array until all options are exhausted. So, if you use an array
 * with a [handler], the handler will make multiple calls for each possible option based on the array items, and if you
 * use them with the [matches] field, then the field will try to validate each possible option as well.
 *
 * @param value source field used to validate the user's [Authorization]. Can be used with contexts. Doesn't work with
 *   string templates.
 * @param matches array containing one or more fields that should match the [value] field for this [Authorize] instance
 *  to be valid. If no [value] field is provided, the [Authorize] instance will be considered valid as long as
 *  the [matches] value exists, for example:
 *  ```kotlin
 *    Authorize(use = ["auth::privileges/users:read"])
 *  ```
 *  If the privilege `privileges/users:read` exists inside the `auth` context, this [Authorize] instance will
 *  be considered valid.
 *
 *  The [Authorize] instance will be considered valid if at least one of the [matches] matches the [value] field.
 *
 * @param handler handler that's used to gather extra data from different services. The handlers can use
 *   their [set][Handler.set] property to set a new [value][Handler.value] inside the `handler` context. This value
 *   can then be used by the next [Authorize] instances.
 */
@Target(allowedTargets = [])
annotation class Authorize(
    val value: String = "",
    val matches: Array<String> = [],
    val handler: Handler = Handler()
)
