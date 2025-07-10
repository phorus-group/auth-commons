package group.phorus.auth.commons.authorization.context

/**
 * Interface for providing authorization context objects.
 */
interface AuthorizationContextProvider {

    /**
     * The context prefix this provider handles (e.g., "auth", "org", "user").
     */
    fun getContextPrefix(): String

    /**
     * Get the context object for this provider.
     *
     * Return any object - the authorization system will use reflection to navigate its properties.
     */
    fun getContextObject(): Any?

    /**
     * Priority for this provider (higher priority = checked first).
     */
    fun getPriority(): Int = 0
}