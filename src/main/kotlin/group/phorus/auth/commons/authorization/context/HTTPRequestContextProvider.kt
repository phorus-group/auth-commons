package group.phorus.auth.commons.authorization.context

import group.phorus.auth.commons.context.HTTPContext
import group.phorus.auth.commons.authorization.context.AuthorizationContextProvider
import org.springframework.boot.autoconfigure.AutoConfiguration

/**
 * HTTP request context provider.
 *
 * Returns the actual HTTPContextData object, which can then be navigated:
 * - httpRequest::path → request path
 * - httpRequest::method → HTTP method
 * - httpRequest::queryParams[search] → query parameter value
 */
@AutoConfiguration
class HTTPRequestContextProvider : AuthorizationContextProvider {

    override fun getContextPrefix(): String = "httpRequest"

    override fun getContextObject(): Any? {
        return HTTPContext.context.get()
    }

    override fun getPriority(): Int = 50
}