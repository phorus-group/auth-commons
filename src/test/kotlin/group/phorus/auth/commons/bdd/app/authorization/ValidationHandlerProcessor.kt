package group.phorus.auth.commons.bdd.app.authorization

import group.phorus.auth.commons.authorization.Handler
import group.phorus.auth.commons.authorization.handler.AuthorizationHandlerProcessor
import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.context.HTTPContext
import org.springframework.stereotype.Component

/**
 * Processor for ValidationHandler - performs rules-based validation with configurable scoring.
 *
 * Supports multiple validation types:
 * - strictMode: Calculates validation score with optional strict HTTP method checking
 * - rulesBased: Evaluates privilege and property rules with threshold scoring
 * - complex: Multi-factor validation including admin privilege, IP address, and user agent
 *
 * Used for testing custom authorization handler functionality.
 */
@Component
class ValidationHandlerProcessor : AuthorizationHandlerProcessor<ValidationHandler> {

    override suspend fun execute(
        config: ValidationHandler,
        entity: Any?,
        handlerContexts: Map<String, Any>
    ): Any? {
        return try {
            when (config.validationType) {
                "strictMode" -> {
                    val authContext = AuthContext.context.get()
                    val httpContext = HTTPContext.context.get()
                    
                    val score = calculateValidationScore(authContext?.privileges ?: emptyList(), config)
                    val isValid = if (config.strictMode) {
                        score >= config.threshold && httpContext?.method?.name() == "GET"
                    } else {
                        score >= config.threshold
                    }
                    
                    mapOf(
                        "isValid" to isValid,
                        "score" to score,
                        "threshold" to config.threshold,
                        "strictMode" to config.strictMode,
                        "validationType" to config.validationType
                    )
                }
                "rulesBased" -> {
                    val authContext = AuthContext.context.get()
                    val userPrivileges = authContext?.privileges ?: emptyList()
                    
                    val passedRules = config.rules.count { rule ->
                        when {
                            rule.startsWith("privilege:") -> {
                                val requiredPrivilege = rule.substringAfter("privilege:")
                                userPrivileges.contains(requiredPrivilege)
                            }
                            rule.startsWith("property:") -> {
                                val propertyCheck = rule.substringAfter("property:")
                                val (key, expectedValue) = propertyCheck.split("=")
                                authContext?.properties?.get(key) == expectedValue
                            }
                            rule == "admin" -> userPrivileges.contains("admin")
                            else -> false
                        }
                    }
                    
                    val totalRules = config.rules.size
                    val validationScore = if (totalRules > 0) (passedRules * 100) / totalRules else 100
                    
                    mapOf(
                        "isValid" to (validationScore >= config.threshold),
                        "passedRules" to passedRules,
                        "totalRules" to totalRules,
                        "validationScore" to validationScore,
                        "threshold" to config.threshold
                    )
                }
                "complex" -> {
                    val authContext = AuthContext.context.get()
                    val httpContext = HTTPContext.context.get()
                    
                    val hasAdminPrivilege = authContext?.privileges?.contains("admin") == true
                    val isInternalIP = httpContext?.remoteAddress?.startsWith("10.") == true
                    val hasValidUserAgent = httpContext?.userAgent?.isNotBlank() == true
                    
                    val complexScore = listOf(hasAdminPrivilege, isInternalIP, hasValidUserAgent)
                        .count { it } * 33
                    
                    mapOf(
                        "isValid" to (complexScore >= config.threshold),
                        "complexScore" to complexScore,
                        "hasAdminPrivilege" to hasAdminPrivilege,
                        "isInternalIP" to isInternalIP,
                        "hasValidUserAgent" to hasValidUserAgent,
                        "threshold" to config.threshold
                    )
                }
                else -> {
                    mapOf("isValid" to false, "error" to "Unknown validation type: ${config.validationType}")
                }
            }
        } catch (e: Exception) {
            mapOf("isValid" to false, "error" to e.message)
        }
    }
    
    private fun calculateValidationScore(privileges: List<String>, config: ValidationHandler): Int {
        val baseScore = when {
            privileges.contains("admin") -> 100
            privileges.contains("manager") -> 80
            privileges.contains("user") -> 60
            else -> 20
        }
        
        val bonusScore = privileges.count { it.contains(":") } * 5
        return minOf(100, baseScore + bonusScore)
    }
}

data class ValidationHandler(
    val validationType: String,
    val threshold: Int = 50,
    val strictMode: Boolean = false,
    val rules: List<String> = emptyList(),
    override val saveTo: String = "validation"
) : Handler
