package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.context.ApiKeyContext
import group.phorus.auth.commons.context.AuthContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api-key-protected")
class ApiKeyProtectedController {

    @GetMapping("/identity")
    suspend fun identity(): Map<String, Any?> {
        val apiKey = ApiKeyContext.context.get()
        return mapOf(
            "keyId" to apiKey.keyId,
            "metadata" to apiKey.metadata,
        )
    }

    @GetMapping("/dual")
    suspend fun dual(): Map<String, Any?> {
        val apiKey = ApiKeyContext.context.get()
        val auth = AuthContext.context.get()
        return mapOf(
            "keyId" to apiKey.keyId,
            "userId" to auth.userId.toString(),
            "privileges" to auth.privileges,
        )
    }
}
