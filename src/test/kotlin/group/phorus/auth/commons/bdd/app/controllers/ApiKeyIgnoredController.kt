package group.phorus.auth.commons.bdd.app.controllers

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api-key-ignored")
class ApiKeyIgnoredController {

    @GetMapping("/public")
    suspend fun publicEndpoint(): Map<String, String> =
        mapOf("status" to "ok")
}
