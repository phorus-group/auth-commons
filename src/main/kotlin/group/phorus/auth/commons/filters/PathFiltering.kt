package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.Path
import group.phorus.auth.commons.config.PrivilegeGate
import group.phorus.exception.handling.Forbidden
import org.springframework.http.HttpMethod
import org.springframework.http.server.PathContainer
import org.springframework.web.util.pattern.PathPatternParser

/**
 * Determines whether a filter should skip the given request path based on the configured
 * [ignoredPaths] and [protectedPaths].
 *
 * Only one of [ignoredPaths] or [protectedPaths] may be non-empty at a time.
 * This constraint is validated at startup in the filter constructors.
 *
 * - **[ignoredPaths]**: the filter runs on all paths **except** the listed ones.
 * - **[protectedPaths]**: the filter runs **only** on the listed paths; everything else is skipped.
 *
 * ### Path matching
 *
 * All paths use Spring [PathPattern][org.springframework.web.util.pattern.PathPattern] syntax.
 * For details of the path pattern syntax see [PathPattern][org.springframework.web.util.pattern.PathPattern].
 *
 * @return `true` when the filter should skip this request (i.e. not enforce authentication).
 */
internal fun shouldSkipPath(
    ignoredPaths: List<Path>,
    protectedPaths: List<Path>,
    path: String,
    method: HttpMethod,
): Boolean {
    if (protectedPaths.isNotEmpty()) {
        val isProtected = protectedPaths.any { matchesPath(it, path, method) }
        return !isProtected
    }

    if (ignoredPaths.isNotEmpty()) {
        return ignoredPaths.any { matchesPath(it, path, method) }
    }

    return false
}

/**
 * Checks that the authenticated user holds the required privileges for the incoming request,
 * according to the configured [gates].
 *
 * ### Evaluation semantics
 *
 * - **OR within a gate**: any one privilege in a gate's list is sufficient to satisfy that gate.
 * - **AND across gates**: all gates matching the request path must independently be satisfied.
 *
 * Gates with an empty [PrivilegeGate.privileges] list are skipped (no restriction imposed).
 * Throws [Forbidden] if any matching gate is not satisfied by [userPrivileges].
 *
 * @param gates The configured privilege gates.
 * @param path The incoming request path.
 * @param method The incoming request HTTP method.
 * @param userPrivileges The authenticated user's privileges from the validated token.
 */
internal fun checkPrivilegeGates(
    gates: List<PrivilegeGate>,
    path: String,
    method: HttpMethod,
    userPrivileges: List<String>,
) {
    val matchingGates = gates.filter { gate ->
        gate.privileges.isNotEmpty() && matchesPath(gate.path, gate.method, path, method)
    }
    if (matchingGates.isEmpty()) return

    val allSatisfied = matchingGates.all { gate ->
        gate.privileges.any { required -> required in userPrivileges }
    }

    if (!allSatisfied) throw Forbidden("Insufficient privileges for this endpoint")
}

private val pathPatternParser = PathPatternParser()

/**
 * Checks if a request path matches the configured path pattern using Spring PathPattern semantics.
 * For details of the path pattern syntax see [PathPattern][org.springframework.web.util.pattern.PathPattern].
 *
 * @param pathConfig The configured path pattern and optional HTTP method constraint.
 * @param requestPath The incoming request path to match against.
 * @param requestMethod The incoming request HTTP method.
 * @return `true` if the request path matches the pattern and the method matches (if specified).
 */
private fun matchesPath(pathConfig: Path, requestPath: String, requestMethod: HttpMethod): Boolean =
    matchesPath(pathConfig.path, pathConfig.method, requestPath, requestMethod)

/**
 * Checks if a request path matches a pattern and optional method constraint.
 * For details of the path pattern syntax see [PathPattern][org.springframework.web.util.pattern.PathPattern].
 *
 * @param pathPattern Spring PathPattern string to match against.
 * @param methodConstraint Optional HTTP method string (e.g. `"POST"`). When `null`, all methods match.
 * @param requestPath The incoming request path.
 * @param requestMethod The incoming request HTTP method.
 * @return `true` if the path matches the pattern and the method matches (if specified).
 */
private fun matchesPath(
    pathPattern: String,
    methodConstraint: String?,
    requestPath: String,
    requestMethod: HttpMethod,
): Boolean {
    val pattern = pathPatternParser.parse(pathPattern)
    val pathMatches = pattern.matches(PathContainer.parsePath(requestPath))
    return pathMatches && (methodConstraint == null || HttpMethod.valueOf(methodConstraint) == requestMethod)
}