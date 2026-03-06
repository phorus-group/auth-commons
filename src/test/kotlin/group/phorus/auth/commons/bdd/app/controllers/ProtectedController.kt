package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.context.AuthContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/protected")
class ProtectedController {

    @GetMapping("/me")
    suspend fun me(): Map<String, Any> {
        val auth = AuthContext.context.get()
        return mapOf(
            "userId" to auth.userId.toString(),
            "privileges" to auth.privileges,
        )
    }
}
