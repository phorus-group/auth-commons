package group.phorus.auth.commons.authorization.context

import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.authorization.context.AuthorizationContextProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.stereotype.Component

/**
 * Authentication context provider.
 *
 * Returns the actual AuthContextData object, which can then be navigated:
 * - auth::userId → authContext.userId
 * - auth::privileges/admin → checks if "admin" exists in authContext.privileges
 */
@AutoConfiguration
class AuthContextProvider : AuthorizationContextProvider {

    override fun getContextPrefix(): String = "auth"

    override fun getContextObject(): Any? {
        return AuthContext.context.get()
    }

    override fun getPriority(): Int = 100
}