package group.phorus.auth.commons.filters

import group.phorus.auth.commons.config.Path
import org.springframework.http.HttpMethod

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

private fun matchesPath(pathConfig: Path, requestPath: String, requestMethod: HttpMethod): Boolean =
    requestPath.startsWith(pathConfig.path) &&
        (pathConfig.method == null || HttpMethod.valueOf(pathConfig.method!!) == requestMethod)
