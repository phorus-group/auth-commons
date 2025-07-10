package group.phorus.auth.commons.bdd.app.authorization

import group.phorus.auth.commons.authorization.Handler
import group.phorus.auth.commons.authorization.handler.AuthorizationHandlerProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.util.*

/**
 * Database permission handler processor for authorization using JDBC.
 *
 * Uses JdbcTemplate for direct database queries to avoid circular dependency
 * with EntityManagerFactory. Performs real database queries to check document
 * ownership and user existence.
 *
 * Returns permission data based on actual database state without requiring
 * JPA repositories or EntityManagerFactory.
 */
@Component
class DatabasePermissionHandlerProcessor(
    private val jdbcTemplate: JdbcTemplate,
) : AuthorizationHandlerProcessor<DatabasePermissionHandler> {

    override suspend fun execute(
        config: DatabasePermissionHandler,
        entity: Any?,
        handlerContexts: Map<String, Any>
    ): Any? {
        return try {
            withContext(Dispatchers.IO) {
                when (config.resourceType) {
                    "document" -> {
                        val documentExists = checkDocumentExists(config.resourceId)
                        val userExists = checkUserExists(config.userId)

                        if (documentExists && userExists) {
                            val documentOwnerId = getDocumentOwnerId(config.resourceId)
                            val hasAccess = documentOwnerId == config.userId

                            mapOf(
                                "hasAccess" to hasAccess,
                                "resourceId" to config.resourceId,
                                "userId" to config.userId,
                                "resourceType" to config.resourceType,
                                "ownerId" to documentOwnerId,
                                "timestamp" to System.currentTimeMillis()
                            )
                        } else {
                            mapOf(
                                "hasAccess" to false,
                                "error" to "Resource or user not found",
                                "resourceId" to config.resourceId,
                                "userId" to config.userId,
                                "resourceType" to config.resourceType,
                                "documentExists" to documentExists,
                                "userExists" to userExists
                            )
                        }
                    }
                    "user" -> {
                        val userExists = checkUserExists(config.resourceId)
                        mapOf(
                            "hasAccess" to userExists,
                            "resourceId" to config.resourceId,
                            "userId" to config.userId,
                            "resourceType" to config.resourceType,
                            "userExists" to userExists
                        )
                    }
                    else -> {
                        mapOf(
                            "hasAccess" to false,
                            "error" to "Unknown resource type: ${config.resourceType}",
                            "resourceId" to config.resourceId,
                            "userId" to config.userId,
                            "resourceType" to config.resourceType
                        )
                    }
                }
            }
        } catch (e: Exception) {
            mapOf(
                "hasAccess" to false,
                "error" to e.message,
                "resourceId" to config.resourceId,
                "userId" to config.userId,
                "resourceType" to config.resourceType,
                "exception" to e.javaClass.simpleName
            )
        }
    }

    /**
     * Checks if a document exists in the database.
     */
    private fun checkDocumentExists(resourceId: String): Boolean {
        return try {
            val uuid = UUID.fromString(resourceId)
            val count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM documents WHERE id = ?",
                Int::class.java,
                uuid
            ) ?: 0
            count > 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks if a user exists in the database.
     */
    private fun checkUserExists(userId: String): Boolean {
        return try {
            val uuid = UUID.fromString(userId)
            val count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users WHERE id = ?",
                Int::class.java,
                uuid
            ) ?: 0
            count > 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Gets the owner ID of a document.
     */
    private fun getDocumentOwnerId(resourceId: String): String? {
        return try {
            val uuid = UUID.fromString(resourceId)
            val ownerId = jdbcTemplate.queryForObject(
                "SELECT owner_id FROM documents WHERE id = ?",
                UUID::class.java,
                uuid
            )
            ownerId?.toString()
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * Configuration for database permission handler.
 */
data class DatabasePermissionHandler(
    val userId: String,
    val resourceId: String,
    val resourceType: String = "document",
    override val saveTo: String = "dbPermissions"
) : Handler