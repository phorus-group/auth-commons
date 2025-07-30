package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.authorization.context.AuthorizationContextProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.stereotype.Service

/**
 * Service that processes context and entity references using reflection.
 *
 * This processor handles all types of context and entity operations used in authorization annotations.
 *
 * ## Supported Path Syntax:
 * - Context properties: `auth::userId`, `org::currentRole`
 * - Entity properties: `::userId`, `::addresses[0]/street`
 * - Nested objects: `auth::user/profile/email/domain`, `::owner/organization/name`
 * - Array/List access: `auth::managedDepartments[0]/employees[5]/profile/skills[0]/name`
 * - Map access: `auth::settings[database]/connections[primary]/replicas[0]/host`
 * - Collection membership: `auth::user/permissions/organizations[123]/roles/admin`
 * - Mixed notation: `auth::tenant/services[auth]/config/endpoints[login]/security/methods[0]/type`
 * - Entity relationships: `::addresses[0]/city`, `::department/employees[5]/skills/java`
 *
 * ## Examples:
 * ```
 * auth::organization/departments[Engineering]/teams[Backend]/members[0]/profile/certifications[AWS]/expiryDate
 * ::owner/addresses[home]/coordinates/latitude
 * auth::user/workspaces[main]/projects[0]/environments[staging]/secrets[apiKey]/value
 * ::department/employees[0]/skills[backend]/proficiency
 * ```
 */
@AutoConfiguration
@Service
class AuthorizationReferenceProcessor(
    private val contextProviders: List<AuthorizationContextProvider>,
    private val objectProcessor: ObjectProcessor,
) {

    private val contextRegistry: Map<String, AuthorizationContextProvider> =
        contextProviders
            .sortedBy { it.getPriority() }
            .associateBy { it.getContextPrefix() } // We keep the highest priority contexts with the same prefix

    /**
     * Resolves a context or entity reference and returns the actual value.
     *
     * This is the primary method for getting values from context objects and entities.
     * Uses reflection to navigate object properties, arrays, maps, and collections.
     *
     * ## Context Examples:
     * - `auth::userId` → returns user ID from auth context
     * - `auth::privileges/admin` → returns true if "admin" exists in privileges collection
     * - `auth::user/profile/settings[theme]/colors/primary` → navigates 5 levels deep in context
     *
     * ## Entity Examples:
     * - `::userId` → returns user ID from entity
     * - `::addresses[0]/street` → returns street from first address
     * - `::department/employees[0]/skills/java` → navigates through entity relationships
     * - `::owner/organization/settings/billing/contact` → deep entity navigation
     *
     * @param reference The context or entity reference to resolve
     * @param entity The entity object (required for entity references)
     * @param extraContexts Additional contexts
     * @return The resolved value (any type), or null if not found/invalid
     */
    fun resolveValue(
        reference: String,
        entity: Any? = null,
        extraContexts: Map<String, Any> = emptyMap()
    ): Any? {
        val (prefix, path) = parseReference(reference) ?: return null

        val rootObject = when {
            prefix.isEmpty() -> entity ?: return null // Entity reference (::property)
            extraContexts.containsKey(prefix) -> extraContexts[prefix] ?: return null // Extra context
            else -> getContextObject(prefix) ?: return null // Regular context
        }

        return objectProcessor.navigateObject(rootObject, path)
    }

    /**
     * Checks if a context or entity reference exists and has a non-null value.
     *
     * @param reference The context or entity reference to check
     * @param entity The entity object (required for entity references)
     * @param extraContexts Additional contexts
     * @return true if the reference exists and has a non-null value, false otherwise
     */
    fun exists(
        reference: String,
        entity: Any? = null,
        extraContexts: Map<String, Any> = emptyMap()
    ): Boolean {
        return resolveValue(reference, entity, extraContexts) != null
    }

    /**
     * Checks if any of multiple context or entity references exist.
     *
     * @param references Array of context or entity references to check
     * @param entity The entity object (required for entity references)
     * @param extraContexts Additional contexts
     * @return true if ANY reference exists, false if NONE exist
     */
    fun existsAny(
        references: Array<String>,
        entity: Any? = null,
        extraContexts: Map<String, Any> = emptyMap()
    ): Boolean {
        return references.any { reference ->
            runCatching {
                exists(reference, entity, extraContexts)
            }.getOrElse { false }
        }
    }

    /**
     * Compares two values which can be either context references or entity properties.
     *
     * @param value1 First value (context reference or entity property name)
     * @param value2 Second value (context reference or entity property name)
     * @param entity Entity object for property resolution (required for entity references)
     * @param extraContexts Additional contexts
     * @return true if values are equal, false otherwise
     */
    fun compareValues(
        value1: String,
        value2: String,
        entity: Any?,
        extraContexts: Map<String, Any> = emptyMap()
    ): Boolean {
        return runCatching {
            val resolved1 = resolveValue(value1, entity, extraContexts)
            val resolved2 = resolveValue(value2, entity, extraContexts)
            objectProcessor.compareValues(resolved1, resolved2)
        }.getOrElse { false }
    }

    /**
     * Resolves template strings with context and entity references.
     *
     * ## Template Syntax:
     * - Context variables: `${<contextRef>}`
     * - Entity variables: `${::<entityPath>}`
     * - Mixed content: Literal text combined with deep context and entity variables
     * - Multiple variables: Each can use different sources and nesting depths
     *
     * ## Examples:
     * - `"organization-${auth::organizationId}"` → `"organization-12345"`
     * - `"/api/users/${auth::userId}/permissions"` → `"/api/users/user123/permissions"`
     * - `"user-${::id}-${::department/code}"` → `"user-123-ENG"`
     *
     * @param template The template string to resolve (variables support deep navigation)
     * @param entity Entity object for entity variable resolution
     * @param extraContexts Additional contexts
     * @return The resolved string with all variables substituted, or null if any variable fails
     */
    fun resolveTemplate(
        template: String,
        entity: Any? = null,
        extraContexts: Map<String, Any> = emptyMap()
    ): String? {
        return runCatching {
            var resolved = template

            val templatePattern = Regex("""\$\{([^}]+)}""")
            templatePattern.findAll(template).forEach { match ->
                val templateKey = match.groupValues[1]
                val templateValue = if (templateKey.contains("::")) {
                    // Context or entity reference with potential deep navigation
                    resolveValue(templateKey, entity, extraContexts)?.toString()
                } else {
                    templateKey // literal value
                } ?: return null // Fail if any variable cannot be resolved

                resolved = resolved.replace(match.value, templateValue)
            }

            resolved
        }.getOrNull()
    }

    /**
     * Gets all available context prefixes for debugging and introspection.
     */
    fun getAvailableContexts(): Set<String> {
        return contextRegistry.keys
    }

    /**
     * Gets the context object for a given prefix.
     */
    fun getContextObject(prefix: String): Any? {
        return contextRegistry[prefix]?.getContextObject()
    }

    /**
     * Navigates an object using the ObjectProcessor.
     *
     * This is a convenience method for external use when you already have the root object.
     *
     * @param obj The root object to navigate
     * @param path The property path to navigate
     * @return The resolved value, or null if not found/invalid
     */
    fun navigateObject(obj: Any, path: String): Any? {
        return objectProcessor.navigateObject(obj, path)
    }

    /**
     * Parses a context or entity reference into prefix and path components.
     *
     * Only splits on the FIRST "::" occurrence to handle cases where the path itself
     * contains "::" (e.g., in collection keys like "settings[api::endpoint]/url").
     *
     * ## Supported Formats:
     * - Context reference: `"auth::userId"` → ("auth", "userId")
     * - Entity reference: `"::userId"` → ("", "userId")
     * - Complex paths: `"auth::user/settings[api::endpoint]/url"` → ("auth", "user/settings[api::endpoint]/url")
     *
     * @param reference The reference string to parse
     * @return Pair of (prefix, path) where empty prefix indicates entity reference, or null if invalid format
     */
    private fun parseReference(reference: String): Pair<String, String>? {
        val firstDoubleColonIndex = reference.indexOf("::")
        if (firstDoubleColonIndex == -1) return null

        val prefix = reference.substring(0, firstDoubleColonIndex)
        val path = reference.substring(firstDoubleColonIndex + 2)

        // Empty prefix means entity reference (::property)
        // Non-empty prefix means context reference (prefix::property)
        return Pair(prefix, path)
    }
}