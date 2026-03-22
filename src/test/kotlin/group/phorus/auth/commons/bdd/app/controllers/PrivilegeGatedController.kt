package group.phorus.auth.commons.bdd.app.controllers

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/privilege-gated")
class PrivilegeGatedController {

    @GetMapping("/admin")
    suspend fun admin(): Map<String, String> = mapOf("status" to "ok")

    @GetMapping("/content")
    suspend fun content(): Map<String, String> = mapOf("status" to "ok")

    @GetMapping("/reports")
    suspend fun getReports(): Map<String, String> = mapOf("status" to "ok")

    @PostMapping("/reports")
    suspend fun postReports(): Map<String, String> = mapOf("status" to "ok")

    @GetMapping("/dual")
    suspend fun dual(): Map<String, String> = mapOf("status" to "ok")
}
