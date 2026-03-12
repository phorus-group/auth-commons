package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.Path
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
private fun matchesPath(pathConfig: Path, requestPath: String, requestMethod: HttpMethod): Boolean {
    val pattern = pathPatternParser.parse(pathConfig.path)
    val pathMatches = pattern.matches(PathContainer.parsePath(requestPath))

    return pathMatches && (pathConfig.method == null || HttpMethod.valueOf(pathConfig.method!!) == requestMethod)
}