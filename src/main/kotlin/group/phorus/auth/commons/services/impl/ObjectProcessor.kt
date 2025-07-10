package group.phorus.auth.commons.services.impl

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.stereotype.Service
import kotlin.collections.get
import kotlin.reflect.full.memberProperties

/**
 * Service for navigating and processing objects using reflection.
 */
@AutoConfiguration
@Service
class ObjectProcessor {
    /**
     * Navigates an object using a property path with bracket notation support.
     *
     * This is the core navigation engine that handles all types of object traversal
     * using reflection and property access.
     *
     * ## Supported Operations:
     * - Simple properties: `userId`, `profile`, `settings`
     * - Nested objects: `user/profile/email/domain/extension`
     * - Array access: `departments[0]/teams[5]/members[10]/skills[2]/name`
     * - Map access: `settings[database]/connections[primary]/replicas[0]/config[timeout]`
     * - Collection membership: `privileges/admin` (admin is a string in the privileges collection)
     *
     * ## Path Parsing Algorithm:
     * 1. Split path by `/` to get navigation segments
     * 2. Each segment can be:
     *    - Simple property: `email`, `profile`, `settings`
     *    - Bracket notation: `departments[HR]`, `items[0]`, `configs[production]`
     *    - Collection membership: `privileges` (when checking for `privileges/admin`)
     *
     * ## Navigation Process:
     * 1. Start with root object
     * 2. For each path segment:
     *    a. Parse segment (simple property vs bracket notation)
     *    b. Navigate one level deeper using reflection
     *    c. Handle type-specific operations (Map, Array, Object, Collection)
     *    d. Update current object reference
     *    e. Continue to next segment
     * 3. Repeat until all segments processed or null encountered
     * 4. Return final resolved value
     *
     * @param obj The root object to start navigation from
     * @param path The complete property path to navigate
     * @return The final resolved value, or null if any step fails
     */
    fun navigateObject(obj: Any, path: String): Any? {
        if (path.isEmpty()) return obj

        val segments = parsePath(path)
        var current: Any? = obj

        // Process each segment sequentially
        for (i in segments.indices) {
            val segment = segments[i]
            val isLastSegment = i == segments.size - 1

            current = when {
                current == null -> return null

                // Handle bracket notation: property[key] or property[index]
                // Examples: settings[theme], employees[0], configs[production], addresses[home]
                segment.isBracketNotation -> {
                    val propertyName = segment.property
                    val key = segment.bracketKey!!

                    // Step 1: Get the property object (e.g., get 'settings' from current object)
                    val propertyValue = getObjectProperty(current, propertyName)
                    if (propertyValue == null) return null

                    // Step 2: Access by key/index (e.g., settings["theme"] or employees[0])
                    // The result becomes the new current object for further navigation
                    accessByKeyOrIndex(propertyValue, key)
                }

                // Handle simple property access
                else -> {
                    val propertyValue = getObjectProperty(current, segment.property)

                    when {
                        // Property exists - use it for further navigation
                        propertyValue != null -> propertyValue

                        // Property is null but this is a collection membership check scenario
                        isLastSegment && (current is Collection<*> || current is Array<*>) -> {
                            // Collection membership check (e.g., checking if "admin" exists in privileges)
                            if (checkCollectionMembership(current, segment.property)) {
                                segment.property // Return the matched value
                            } else {
                                null
                            }
                        }

                        // Property is null and not a collection membership scenario - fail
                        else -> return null
                    }
                }
            }
        }

        return current
    }

    /**
     * Parses a path string into navigation segments with bracket notation support.
     *
     * Converts paths into structured segments for navigation.
     *
     * ## Examples:
     * - `"userId"` → [PathSegment(property="userId")]
     * - `"departments[0]/teams[5]/members[10]"` → 3 segments with bracket notation
     * - `"settings[database]/connections[primary]/config[timeout]/value"` → 4 segments mixed
     *
     * @param path The path string to parse
     * @return List of path segments for navigation
     */
    fun parsePath(path: String): List<PathSegment> {
        val segments = mutableListOf<PathSegment>()
        val parts = path.split("/")

        for (part in parts) {
            if (part.contains("[") && part.endsWith("]")) {
                // Bracket notation: property[key]
                val propertyName = part.substring(0, part.indexOf("["))
                val key = part.substring(part.indexOf("[") + 1, part.length - 1)
                segments.add(PathSegment(propertyName, key, true))
            } else {
                // Simple property
                segments.add(PathSegment(part, null, false))
            }
        }

        return segments
    }

    /**
     * Accesses a collection or map by key or index (BRACKET NOTATION ONLY).
     *
     * @param collection The collection object
     * @param keyOrIndex The key or index from bracket notation
     * @return The accessed value, or null if not found/invalid
     */
    fun accessByKeyOrIndex(
        collection: Any,
        keyOrIndex: String
    ): Any? {
        return runCatching {
            when (collection) {
                is Map<*, *> -> {
                    collection[keyOrIndex]
                }

                is Array<*> -> {
                    val index = keyOrIndex.toIntOrNull()
                    if (index != null && index >= 0 && index < collection.size) {
                        collection[index]
                    } else {
                        null
                    }
                }

                is Collection<*> -> {
                    val index = keyOrIndex.toIntOrNull()
                    val list = collection.toList()
                    if (index != null && index >= 0 && index < list.size) {
                        list[index]
                    } else {
                        null
                    }
                }

                else -> null
            }
        }.getOrNull()
    }

    /**
     * Checks if a value exists in a collection (membership check).
     */
    fun checkCollectionMembership(collection: Any, value: String): Boolean {
        return runCatching {
            when (collection) {
                is Collection<*> -> collection.any { it.toString() == value }
                is Array<*> -> collection.any { it.toString() == value }
                else -> false
            }
        }.getOrElse { false }
    }

    /**
     * Gets a property from an object using reflection or map access.
     *
     * This method enables navigation by returning objects that can be further navigated.
     * Works with context objects, entity objects, and Map-like objects (including LinkedHashMap
     * from REST API responses).
     */
    fun getObjectProperty(obj: Any, propertyName: String): Any? {
        return runCatching {
            // First, check if this is a Map-like object (e.g., LinkedHashMap from REST APIs)
            if (obj is Map<*, *>) {
                return obj[propertyName]
            }

            // Try Kotlin property access (for regular objects)
            obj::class.memberProperties
                .find { it.name == propertyName }
                ?.getter
                ?.call(obj)
        }.getOrElse {
            runCatching {
                // Fall back to Java field access
                val field = obj::class.java.getDeclaredField(propertyName)
                field.isAccessible = true
                field.get(obj)
            }.getOrNull()
        }
    }

    /**
     * Compares two resolved values.
     */
    fun compareValues(value1: Any?, value2: Any?): Boolean {
        return when {
            value1 == null && value2 == null -> true
            value1 == null || value2 == null -> false
            value1::class == value2::class -> value1 == value2
            value1 is Number && value2 is Number -> {
                runCatching {
                    value1.toDouble() == value2.toDouble()
                }.getOrElse {
                    value1.toString() == value2.toString()
                }
            }
            else -> value1.toString() == value2.toString()
        }
    }

    /**
     * Data class representing a parsed path segment.
     */
    data class PathSegment(
        val property: String,
        val bracketKey: String?,
        val isBracketNotation: Boolean
    )
}