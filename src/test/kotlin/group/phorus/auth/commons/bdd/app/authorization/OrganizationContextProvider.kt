package group.phorus.auth.commons.bdd.app.authorization

import group.phorus.auth.commons.authorization.context.AuthorizationContextProvider
import group.phorus.auth.commons.context.AuthContext
import org.springframework.stereotype.Component

@Component
class OrganizationContextProvider : AuthorizationContextProvider {

    override fun getContextPrefix(): String = "org"

    override fun getContextObject(): Any? {
        val authContext = AuthContext.context.get() ?: return null
        
        // In a real application, this would fetch from organization service/database
        // For testing, we create mock organization data based on auth context
        val orgId = authContext.properties["organizationId"] ?: "default-org"
        val deptId = authContext.properties["department"] ?: "general"
        
        return OrganizationContextData(
            organizationId = orgId,
            departmentId = deptId,
            roles = authContext.privileges.filter { it.contains("role:") }
                .map { it.substringAfter("role:") },
            permissions = mapOf(
                "documents" to listOf("read", "write", "delete"),
                "users" to listOf("read"),
                "reports" to if (authContext.privileges.contains("admin")) 
                    listOf("read", "write", "delete") else listOf("read")
            ),
            settings = mapOf(
                "theme" to "corporate",
                "timezone" to "UTC",
                "features" to mapOf(
                    "advancedReporting" to true,
                    "apiAccess" to authContext.privileges.contains("api:access")
                )
            )
        )
    }

    override fun getPriority(): Int = 75
}

data class OrganizationContextData(
    val organizationId: String,
    val departmentId: String,
    val roles: List<String>,
    val permissions: Map<String, List<String>>,
    val settings: Map<String, Any>
)
