package group.phorus.auth.commons.authorization.handler

/**
 * Base interface for authorization handlers that process specific handler configurations.
 *
 * @param T The handler configuration type this processor handles
 */
interface AuthorizationHandlerProcessor<T> {

    /**
     * Execute the handler using the provided configuration.
     *
     * @param config The handler configuration (RESTHandler, GraphQLHandler, etc.)
     * @param entity The entity being accessed
     * @param handlerContexts Previous handler responses within the same @Authorization
     * @return Handler response
     */
    suspend fun execute(
        config: T,
        entity: Any?,
        handlerContexts: Map<String, Any> = emptyMap()
    ): Any?
}