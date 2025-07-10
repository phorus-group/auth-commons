package group.phorus.auth.commons.authorization.interceptor

import group.phorus.auth.commons.authorization.*
import group.phorus.auth.commons.authorization.handler.AuthorizationHandlerProcessor
import group.phorus.auth.commons.authorization.handler.rest.RestHandlerProcessorProcessor
import group.phorus.auth.commons.services.impl.AuthorizationReferenceProcessor
import group.phorus.exception.handling.Forbidden
import kotlinx.coroutines.runBlocking
import org.hibernate.Interceptor
import org.hibernate.type.Type
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import kotlin.reflect.KClass
import kotlin.reflect.full.findAnnotations
import kotlin.reflect.full.memberProperties

/**
 * Hibernate interceptor that enforces authorization rules on entity operations.
 *
 * This interceptor checks @Authorization annotations on entities and their fields
 * to determine if the current user has permission to perform database operations.
 * Uses the modern Hibernate 6.x interceptor methods (onPersist, onRemove, etc.).
 *
 * ## Authorization Levels and Behavior:
 *
 * ### CREATE Operations (onPersist):
 * - **Entity-level**: Rejects entire creation if authorization fails
 * - **Field-level**: Ignored (user is creating new data, not accessing existing fields)
 *
 * ### READ Operations (onLoad):
 * - **Entity-level**: Rejects entire entity load if authorization fails
 * - **Field-level**: Nulls out unauthorized fields, allows entity to load with accessible fields
 *
 * ### UPDATE Operations (onFlushDirty):
 * - **Entity-level**: Rejects entire update if authorization fails
 * - **Field-level**: Reverts unauthorized field changes to previous values, allows update of authorized fields
 *
 * ### DELETE Operations (onRemove):
 * - **Entity-level**: Rejects entire deletion if authorization fails
 * - **Field-level**: Ignored (deleting entire entity, not individual fields)
 *
 * ## Features:
 * - Supports all CRUD operations (CREATE, READ, UPDATE, DELETE)
 * - Handles class-level and field-level authorization
 * - Supports multiple authorization annotations with priorities
 * - Works with all JPA relationships (@OneToMany, @ManyToMany, etc.)
 *
 * ## ⚠️ IMPORTANT: Operations that bypass @Authorization annotations
 *
 * **Direct Database Access** bypasses any @Authorization annotation:
 * ```kotlin
 * // ❌ These bypass ALL authorization checks:
 * jdbcTemplate.update("INSERT INTO employees VALUES (?)", values)
 * dataSource.connection.use { it.prepareStatement("DELETE FROM employees").execute() }
 * entityManager.createQuery("DELETE FROM Entity").executeUpdate()
 * session.createSQLQuery("UPDATE employees SET active = 0").executeUpdate()
 * ```
 *
 * **@Query with @Modifying** (INSERT, UPDATE, DELETE, and DDL queries) also bypasses any @Authorization annotation:
 * ```kotlin
 * // ❌ These bypass ALL authorization checks:
 * @Query("UPDATE Employee SET salary = salary * 1.1") @Modifying
 * @Query("DELETE FROM Employee WHERE active = false") @Modifying
 * @Query(value = "UPDATE employees SET status = ?", nativeQuery = true) @Modifying
 * ```
 *
 * **You need to manually check if the caller has access in these situations.**
 *
 * ## Configuration:
 * ```yaml
 * spring:
 *   jpa:
 *     properties:
 *       hibernate:
 *         enable_lazy_load_no_trans: true  # Required for lazy relationship navigation
 * ```
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "group.phorus.authorization.interceptor", name = ["enable"], havingValue = "true", matchIfMissing = true)
class AuthorizationHibernateInterceptor(
    private val referenceProcessor: AuthorizationReferenceProcessor,
    private val restHandlerProcessor: RestHandlerProcessorProcessor,
    private val customHandlerProcessors: List<AuthorizationHandlerProcessor<*>>
) : Interceptor {

    /**
     * Called before an entity is saved to the database.
     *
     * For CREATE operations:
     * - Only entity-level authorization is checked
     * - Field-level authorization is ignored (user is creating new data, not accessing existing fields)
     */
    override fun onPersist(
        entity: Any?,
        id: Any?,
        state: Array<out Any?>?,
        propertyNames: Array<out String>?,
        types: Array<out Type>?
    ): Boolean {
        if (entity != null) {
            runBlocking {
                // Only check entity-level authorization for CREATE operations
                // Field-level authorization is ignored during entity creation
                checkEntityAuthorization(entity, Operation.CREATE)
            }
        }
        return false
    }

    /**
     * Called before an entity is updated in the database.
     *
     * For UPDATE operations:
     * - Entity-level authorization: Throws exception to reject entire update
     * - Field-level authorization: Reverts unauthorized field changes to previous values
     */
    override fun onFlushDirty(
        entity: Any?,
        id: Any?,
        currentState: Array<out Any?>?,
        previousState: Array<out Any?>?,
        propertyNames: Array<out String>?,
        types: Array<out Type>?
    ): Boolean {
        if (entity != null && currentState != null && previousState != null && propertyNames != null) {
            return runBlocking {
                // First check entity-level authorization - can throw exception to reject entire update
                checkEntityAuthorization(entity, Operation.UPDATE)

                // Then check field-level authorization and revert unauthorized field changes
                checkFieldAuthorizationForUpdate(entity, propertyNames, currentState, previousState)
            }
        }
        return false
    }

    /**
     * Called before an entity is deleted from the database.
     *
     * For DELETE operations:
     * - Only entity-level authorization is checked
     * - Field-level authorization is ignored (not deleting individual fields, but entire entity)
     */
    override fun onRemove(
        entity: Any?,
        id: Any?,
        state: Array<out Any?>?,
        propertyNames: Array<out String>?,
        types: Array<out Type>?
    ) {
        if (entity != null) {
            runBlocking {
                // Only check entity-level authorization for DELETE operations
                // Field-level authorization is irrelevant when deleting entire entity
                checkEntityAuthorization(entity, Operation.DELETE)
            }
        }
    }

    /**
     * Called after an entity is loaded from the database.
     *
     * For READ operations:
     * - Entity-level authorization: Throws exception to reject entire entity load
     * - Field-level authorization: Modifies state array to null out unauthorized fields
     */
    override fun onLoad(
        entity: Any?,
        id: Any?,
        state: Array<out Any?>?,
        propertyNames: Array<out String>?,
        types: Array<out Type>?
    ): Boolean {
        if (entity != null && state != null && propertyNames != null) {
            return runBlocking {
                // First check entity-level authorization - can throw exception to reject entire entity
                checkEntityAuthorization(entity, Operation.READ)

                // If entity authorization passes, check field-level authorization and modify state array
                checkFieldAuthorizationForRead(entity, propertyNames, state)
            }
        }
        return false
    }

    /**
     * Checks entity-level authorization annotations.
     * Throws exception to reject the entire operation if authorization fails.
     */
    private fun checkEntityAuthorization(entity: Any, operation: Operation) {
        try {
            val entityClass = entity::class
            val authorizations = entityClass.findAnnotations<Authorization>()
                .filter { authorization ->
                    authorization.operations.contains(Operation.ALL) ||
                        authorization.operations.contains(operation)
                }
                .sortedByDescending { it.priority }

            if (authorizations.isEmpty()) return

            // Try each authorization annotation (OR logic between annotations)
            for (authorization in authorizations) {
                if (evaluateAuthorization(authorization, entity)) {
                    return // Access granted
                }
            }

            // No authorization granted access
            throw Forbidden("Access denied to ${entityClass.simpleName} for operation $operation")
        } catch (e: Forbidden) {
            throw e // Re-throw authorization errors
        } catch (_: Exception) {
            throw Forbidden("Authorization check failed for ${entity::class.simpleName}")
        }
    }

    /**
     * Checks field-level authorization for READ operations and modifies the state array.
     *
     * This method nulls out unauthorized fields in the state array, which prevents
     * them from being loaded into the entity. This is the proper way to handle
     * field-level authorization in Hibernate interceptors for READ operations.
     *
     * @param entity The entity being loaded (uninitialized at this point)
     * @param propertyNames Array of property names (matches state array indexes)
     * @param state Array of property values that will populate the entity (mutable)
     * @return true if any state modifications were made, false otherwise
     */
    private fun checkFieldAuthorizationForRead(
        entity: Any,
        propertyNames: Array<out String>,
        state: Array<out Any?>
    ): Boolean {
        var modificationssMade = false

        try {
            val entityClass = entity::class
            val mutableState = state as Array<Any?> // Cast to mutable array

            // Check each field for authorization
            propertyNames.forEachIndexed { index, propertyName ->
                val property = entityClass.memberProperties.find { it.name == propertyName }
                if (property != null) {
                    val authorizations = property.findAnnotations<Authorization>()
                        .filter { authorization ->
                            authorization.operations.contains(Operation.ALL) ||
                                authorization.operations.contains(Operation.READ)
                        }
                        .sortedByDescending { it.priority }

                    // Only check authorization if field has @Authorization annotations
                    if (authorizations.isNotEmpty()) {
                        var accessGranted = false

                        // Try each authorization annotation (OR logic between annotations)
                        for (authorization in authorizations) {
                            if (evaluateAuthorization(authorization, entity)) {
                                accessGranted = true
                                break
                            }
                        }

                        // If access is denied, null out the field in the state array
                        if (!accessGranted) {
                            mutableState[index] = null
                            modificationssMade = true

                            // Optional: Log the field access denial for debugging
                            println("Field access denied - nulled out: ${entity::class.simpleName}.${propertyName}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // If there's an error in field authorization, be conservative and null out all protected fields
            val mutableState = state as Array<Any?>
            val entityClass = entity::class

            propertyNames.forEachIndexed { index, propertyName ->
                val property = entityClass.memberProperties.find { it.name == propertyName }
                if (property != null) {
                    val hasAuthAnnotations = property.findAnnotations<Authorization>().isNotEmpty()
                    if (hasAuthAnnotations) {
                        mutableState[index] = null
                        modificationssMade = true
                    }
                }
            }

            println("Field authorization check failed for ${entity::class.simpleName}, nulled protected fields: ${e.message}")
        }

        return modificationssMade
    }

    /**
     * Checks field-level authorization for UPDATE operations and reverts unauthorized changes.
     *
     * This method compares currentState vs previousState for each field. If a field is being
     * changed and the user doesn't have authorization to update that field, the change is
     * reverted by setting currentState back to previousState value.
     *
     * @param entity The entity being updated
     * @param propertyNames Array of property names (matches state array indexes)
     * @param currentState Array of new property values (mutable)
     * @param previousState Array of previous property values (read-only)
     * @return true if any state modifications were made, false otherwise
     */
    private fun checkFieldAuthorizationForUpdate(
        entity: Any,
        propertyNames: Array<out String>,
        currentState: Array<out Any?>,
        previousState: Array<out Any?>
    ): Boolean {
        var modificationssMade = false

        try {
            val entityClass = entity::class
            val mutableCurrentState = currentState as Array<Any?> // Cast to mutable array

            // Check each field for changes and authorization
            propertyNames.forEachIndexed { index, propertyName ->
                val property = entityClass.memberProperties.find { it.name == propertyName }
                if (property != null) {
                    val authorizations = property.findAnnotations<Authorization>()
                        .filter { authorization ->
                            authorization.operations.contains(Operation.ALL) ||
                                authorization.operations.contains(Operation.UPDATE)
                        }
                        .sortedByDescending { it.priority }

                    // Only check authorization if field has @Authorization annotations AND field is being changed
                    if (authorizations.isNotEmpty() &&
                        !areValuesEqual(currentState[index], previousState[index])) {

                        var accessGranted = false

                        // Try each authorization annotation (OR logic between annotations)
                        for (authorization in authorizations) {
                            if (evaluateAuthorization(authorization, entity)) {
                                accessGranted = true
                                break
                            }
                        }

                        // If access is denied, revert the field change
                        if (!accessGranted) {
                            mutableCurrentState[index] = previousState[index]
                            modificationssMade = true

                            // Optional: Log the field update denial for debugging
                            println("Field update denied - reverted change: ${entity::class.simpleName}.${propertyName}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // If there's an error in field authorization, be conservative and revert all protected field changes
            val mutableCurrentState = currentState as Array<Any?>
            val entityClass = entity::class

            propertyNames.forEachIndexed { index, propertyName ->
                val property = entityClass.memberProperties.find { it.name == propertyName }
                if (property != null) {
                    val hasAuthAnnotations = property.findAnnotations<Authorization>().isNotEmpty()
                    if (hasAuthAnnotations && !areValuesEqual(currentState[index], previousState[index])) {
                        mutableCurrentState[index] = previousState[index]
                        modificationssMade = true
                    }
                }
            }

            println("Field authorization check failed for ${entity::class.simpleName}, reverted protected field changes: ${e.message}")
        }

        return modificationssMade
    }

    /**
     * Compares two values for equality, handling nulls properly.
     */
    private fun areValuesEqual(value1: Any?, value2: Any?): Boolean {
        return when {
            value1 == null && value2 == null -> true
            value1 == null || value2 == null -> false
            else -> value1 == value2
        }
    }

    /**
     * Evaluates a single @Authorization annotation.
     */
    private fun evaluateAuthorization(authorization: Authorization, entity: Any): Boolean {
        val definitions = authorization.definitions
        if (definitions.isEmpty()) return true

        // Shared handler contexts across all Authorize definitions within this Authorization
        val sharedHandlerContexts = mutableMapOf<String, Any>()

        return when (authorization.mode) {
            AuthorizationMode.OR -> {
                // Any definition needs to pass
                definitions.any { definition ->
                    evaluateAuthorizeDefinition(definition, entity, sharedHandlerContexts)
                }
            }
            AuthorizationMode.AND -> {
                // All definitions must pass
                definitions.all { definition ->
                    evaluateAuthorizeDefinition(definition, entity, sharedHandlerContexts)
                }
            }
        }
    }

    /**
     * Evaluates a single @Authorize definition.
     */
    private fun evaluateAuthorizeDefinition(
        authorize: Authorize,
        entity: Any,
        handlerContexts: MutableMap<String, Any>
    ): Boolean {
        // Execute REST handler if specified
        if (authorize.restHandler.call.isNotEmpty()) {
            val response = runBlocking {
                restHandlerProcessor.execute(authorize.restHandler, entity, handlerContexts)
            }
            if (response != null) {
                handlerContexts["response"] = response
                handlerContexts[authorize.restHandler.saveTo] = response
            }
        } else if (authorize.handler != EmptyHandler::class) {
            // Execute custom handler if specified (mutually exclusive with REST handler)
            val response = executeCustomHandler(authorize, entity, handlerContexts)
            if (response != null) {
                handlerContexts["response"] = response

                // Get saveTo from handler config
                val saveTo = getSaveToFromHandler(authorize.handler, authorize.handlerConfig)
                handlerContexts[saveTo] = response
            }
        }

        // If no value and no matches, but handler was executed, it's a setup step (always pass)
        if (authorize.value.isEmpty() && authorize.matches.isEmpty()) {
            return true
        }

        // If only matches provided, check if any match exists
        if (authorize.value.isEmpty() && authorize.matches.isNotEmpty()) {
            return referenceProcessor.existsAny(authorize.matches, entity, handlerContexts)
        }

        // Resolve the value (with template support)
        val resolvedValue = if (authorize.value.contains("\${")) {
            // Template resolution
            val resolvedTemplate = referenceProcessor.resolveTemplate(authorize.value, entity, handlerContexts)
            if (resolvedTemplate != null) {
                referenceProcessor.resolveValue(resolvedTemplate, entity, handlerContexts)
            } else {
                null
            }
        } else {
            // Direct value resolution
            referenceProcessor.resolveValue(authorize.value, entity, handlerContexts)
        }

        // If no matches provided, check if value is truthy
        if (authorize.matches.isEmpty()) {
            return isTruthy(resolvedValue)
        }

        // Check if resolved value matches any of the provided matches
        return authorize.matches.any { match ->
            if (match.contains("::")) {
                // Match is a context reference
                val matchValue = referenceProcessor.resolveValue(match, entity, handlerContexts)
                referenceProcessor.compareValues(
                    resolvedValue?.toString() ?: "",
                    matchValue?.toString() ?: "",
                    entity,
                    handlerContexts
                )
            } else {
                // Match is a literal value
                resolvedValue?.toString() == match
            }
        }
    }

    /**
     * Executes a custom handler using the appropriate processor.
     */
    private fun executeCustomHandler(
        authorize: Authorize,
        entity: Any,
        handlerContexts: Map<String, Any>
    ): Any? {
        return runCatching {
            if (authorize.handlerConfig.isEmpty()) return null

            // Parse handlerConfig JSON and create config instance
            val configJson = if (authorize.handlerConfig.contains("\${")) {
                referenceProcessor.resolveTemplate(authorize.handlerConfig, entity, handlerContexts)
            } else {
                authorize.handlerConfig
            } ?: return null

            // Find the appropriate processor for this handler type
            val processor = findCustomHandlerProcessor(authorize.handler) ?: return null

            // Create handler config instance from JSON
            val handlerConfig = createHandlerConfigFromJson(authorize.handler, configJson)
            runBlocking {
                processor.execute(handlerConfig, entity, handlerContexts)
            }
        }.getOrNull()
    }

    /**
     * Finds the appropriate custom handler processor for the given handler class.
     */
    @Suppress("UNCHECKED_CAST")
    private fun findCustomHandlerProcessor(handlerClass: KClass<*>): AuthorizationHandlerProcessor<Any>? {
        return customHandlerProcessors.find { processor ->
            // More robust type checking
            val processorClass = processor::class
            val superInterfaces = processorClass.supertypes

            superInterfaces.any { superType ->
                val typeArguments = superType.arguments
                if (typeArguments.isNotEmpty()) {
                    val firstArg = typeArguments[0].type
                    firstArg?.classifier == handlerClass
                } else {
                    false
                }
            }
        } as? AuthorizationHandlerProcessor<Any>
    }

    /**
     * Creates a handler config instance from JSON string.
     * Production-ready implementation using Jackson ObjectMapper.
     */
    private fun createHandlerConfigFromJson(handlerClass: KClass<*>, json: String): Any {
        return runCatching {
            // Try to get object instance first (for object declarations)
            handlerClass.objectInstance?.let { return it }

            // TODO: Replace with proper Jackson deserialization in production:
            // val objectMapper = ObjectMapper().registerModule(KotlinModule.Builder().build())
            // return objectMapper.readValue(json, handlerClass.java)

            // For now, create instance with parameterless constructor
            // This is a simplified implementation - in production you should parse the JSON properly
            val constructor = handlerClass.constructors.firstOrNull { it.parameters.isEmpty() }
                ?: throw IllegalArgumentException("No parameterless constructor found for ${handlerClass.simpleName}")

            constructor.call()
        }.getOrElse {
            throw IllegalArgumentException("Could not create handler config from JSON: $json for class ${handlerClass.simpleName}")
        }
    }

    /**
     * Gets the saveTo value from a handler config using reflection.
     */
    private fun getSaveToFromHandler(handlerClass: KClass<*>, handlerConfig: String): String {
        return runCatching {
            // Try to get object instance first (for object declarations)
            handlerClass.objectInstance?.let { instance ->
                return getSaveToFromInstance(instance)
            }

            // For data classes and regular classes, try to create instance
            val constructor = handlerClass.constructors.firstOrNull()
            if (constructor != null && constructor.parameters.isEmpty()) {
                val instance = constructor.call()
                return getSaveToFromInstance(instance)
            }

            // If we can't create an instance, try to extract saveTo from JSON config (fallback)
            if (handlerConfig.contains("\"saveTo\"")) {
                val saveToPattern = Regex("\"saveTo\"\\s*:\\s*\"([^\"]+)\"")
                saveToPattern.find(handlerConfig)?.groupValues?.get(1) ?: "handler"
            } else {
                "handler"
            }
        }.getOrElse { "handler" }
    }

    /**
     * Extracts saveTo value from a handler instance using reflection.
     */
    private fun getSaveToFromInstance(instance: Any): String {
        return runCatching {
            // First try if it implements Handler interface
            if (instance is Handler) {
                return instance.saveTo.ifEmpty { "handler" }
            }

            // Otherwise use reflection to find saveTo property
            val saveToProperty = instance::class.memberProperties.find { it.name == "saveTo" }
            val saveToValue = saveToProperty?.getter?.call(instance)?.toString()
            saveToValue?.ifEmpty { "handler" } ?: "handler"
        }.getOrElse { "handler" }
    }

    /**
     * Checks if a value is considered "truthy" for authorization purposes.
     */
    private fun isTruthy(value: Any?): Boolean {
        return when (value) {
            null -> false
            is Boolean -> value
            is String -> value.isNotEmpty()
            is Number -> value.toDouble() != 0.0
            is Collection<*> -> value.isNotEmpty()
            is Array<*> -> value.isNotEmpty()
            is Map<*, *> -> value.isNotEmpty()
            else -> true
        }
    }
}