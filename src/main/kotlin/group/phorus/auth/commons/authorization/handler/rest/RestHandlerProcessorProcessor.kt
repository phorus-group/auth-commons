package group.phorus.auth.commons.authorization.handler.rest

import group.phorus.auth.commons.authorization.handler.AuthorizationHandlerProcessor
import group.phorus.auth.commons.services.impl.AuthorizationReferenceProcessor
import group.phorus.auth.commons.config.AuthorizationProperties
import group.phorus.auth.commons.context.HTTPContext
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import kotlinx.coroutines.withTimeout
import org.springframework.boot.autoconfigure.AutoConfiguration

/**
 * REST handler processor for making HTTP calls to external services during authorization.
 */
@AutoConfiguration
class RestHandlerProcessorProcessor(
    private val properties: AuthorizationProperties,
    private val processor: AuthorizationReferenceProcessor,
) : AuthorizationHandlerProcessor<RESTHandler> {

    private val webClient: WebClient by lazy {
        WebClient.builder().build()
    }

    /**
     * Executes a REST API call based on the provided configuration.
     *
     * @param config The REST handler configuration containing URL, method, and options
     * @param entity The entity being accessed
     * @param handlerContexts Map of temporary contexts for template variable resolution
     * @return The raw response data from the API call, or null if the request failed
     */
    override suspend fun execute(
        config: RESTHandler,
        entity: Any?,
        handlerContexts: Map<String, Any>,
    ): Any? {
        if (config.call.isEmpty()) return null
        return runCatching {
            withTimeout(properties.handler.timeoutMs) {

                val resolvedUrl = processor.resolveTemplate(
                    template = config.call,
                    entity = entity,
                    extraContexts = handlerContexts,
                ) ?: return@withTimeout null

                // Get auth header
                val authHeader = if (config.forwardAuth) {
                    getAuthorizationHeader()
                } else null

                // Execute the HTTP request based on the configured method
                when (config.method) {
                    HTTPMethod.GET -> {
                        webClient.get().uri(resolvedUrl).apply {
                            if (authHeader != null) header("Authorization", authHeader)
                        }.retrieve().awaitBody<Any>()
                    }

                    HTTPMethod.POST -> {
                        webClient.post().uri(resolvedUrl).apply {
                            if (authHeader != null) header("Authorization", authHeader)
                        }.retrieve().awaitBody<Any>()
                    }

                    HTTPMethod.PUT -> {
                        webClient.put().uri(resolvedUrl).apply {
                            if (authHeader != null) header("Authorization", authHeader)
                        }.retrieve().awaitBody<Any>()
                    }

                    HTTPMethod.DELETE -> {
                        webClient.delete().uri(resolvedUrl).apply {
                            if (authHeader != null) header("Authorization", authHeader)
                        }.retrieve().awaitBody<Any>()
                    }
                }
            }
        }.getOrNull()
    }

    private fun getAuthorizationHeader(): String? {
        return HTTPContext.context.get()?.headers?.get("authorization")?.firstOrNull()
    }
}