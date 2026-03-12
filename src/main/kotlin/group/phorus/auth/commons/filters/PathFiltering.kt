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
 * ### Path matching
 *
 * Paths can be specified as either literal prefixes or parameterized patterns:
 *
 * - **Literal prefix**: `/api/public` matches `/api/public`, `/api/public/users`, etc.
 * - **Parameterized pattern**: `/application/{id}/status` matches paths with variable segments.
 *   Parameters can optionally include regex constraints: `/users/{id:\d+}`.
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
 * Checks if a request path matches the configured path pattern.
 *
 * ### Parameterized patterns
 *
 * Path patterns can include parameters using `{name}` or `{name:regex}` syntax:
 *
 * - `{id}` matches any segment (equivalent to `[^/]+`)
 * - `{id:\d+}` matches only digits
 * - `{slug:[a-z0-9-]+}` matches lowercase alphanumeric with dashes
 *
 * Examples:
 * - `/api/users` → literal prefix, matches `/api/users`, `/api/users/123`, etc.
 * - `/users/{id}` → matches `/users/123`, `/users/abc`, but not `/users` or `/users/123/profile`
 * - `/users/{id:\d+}` → matches `/users/123`, but not `/users/abc`
 * - `/application/{id}/status` → matches `/application/abc123/status`
 *
 * @param pathConfig The configured path pattern and optional HTTP method constraint.
 * @param requestPath The incoming request path to match against.
 * @param requestMethod The incoming request HTTP method.
 * @return `true` if the request path matches the pattern and the method matches (if specified).
 */
private fun matchesPath(pathConfig: Path, requestPath: String, requestMethod: HttpMethod): Boolean {
    val pathMatches = if (isParameterizedPattern(pathConfig.path)) {
        val regexPattern = convertToRegex(pathConfig.path)
        requestPath.matches(regexPattern)
    } else {
        requestPath.startsWith(pathConfig.path)
    }

    return pathMatches && (pathConfig.method == null || HttpMethod.valueOf(pathConfig.method!!) == requestMethod)
}

/**
 * Determines if a path string contains parameter placeholders.
 *
 * A path is considered parameterized if it contains `{...}` parameter syntax.
 *
 * @param path The path string to check.
 * @return `true` if the path contains parameters, `false` if it is a literal prefix.
 */
private fun isParameterizedPattern(path: String): Boolean =
    path.contains('{') && path.contains('}')

/**
 * Converts a parameterized path pattern to a regular expression.
 *
 * Transforms parameter syntax into regex:
 * - `{id}` → `[^/]+` (matches any non-slash characters)
 * - `{id:\d+}` → `\d+` (uses the provided regex constraint)
 * - `{slug:[a-z0-9-]+}` → `[a-z0-9-]+`
 *
 * The resulting regex is anchored with `^` and `$` for exact matching.
 *
 * Examples:
 * - `/users/{id}` → `^/users/[^/]+$`
 * - `/users/{id:\d+}` → `^/users/\d+$`
 * - `/application/{id}/status` → `^/application/[^/]+/status$`
 * - `/application/{appId}/codebtor/{debtorId}` → `^/application/[^/]+/codebtor/[^/]+$`
 *
 * @param path The parameterized path pattern.
 * @return A compiled [Regex] for matching request paths.
 */
private fun convertToRegex(path: String): Regex {
    val parameterRegex = Regex("""\{([^:}]+)(?::([^}]+))?\}""")
    
    var regexPattern = StringBuilder("^")
    var lastIndex = 0
    
    parameterRegex.findAll(path).forEach { matchResult ->
        val literalPart = path.substring(lastIndex, matchResult.range.first)
        regexPattern.append(Regex.escape(literalPart))
        
        val constraint = matchResult.groupValues[2]
        if (constraint.isNotEmpty()) {
            regexPattern.append(constraint)
        } else {
            regexPattern.append("[^/]+")
        }
        
        lastIndex = matchResult.range.last + 1
    }
    
    val remainingLiteral = path.substring(lastIndex)
    regexPattern.append(Regex.escape(remainingLiteral))
    regexPattern.append("$")
    
    return Regex(regexPattern.toString())
}
