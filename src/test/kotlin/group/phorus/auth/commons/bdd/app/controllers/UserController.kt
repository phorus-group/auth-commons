package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.bdd.app.dtos.UserDTO
import group.phorus.auth.commons.bdd.app.dtos.UserResponse
import group.phorus.auth.commons.bdd.app.services.UserService
import group.phorus.auth.commons.context.AuthContext
import group.phorus.auth.commons.dtos.AuthContextData
import group.phorus.mapper.mapping.extensions.mapTo
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.net.URI

@RestController
@RequestMapping("/user")
class UserController(
    private val userService: UserService,
) {
    @GetMapping
    suspend fun findCurrent(@RequestHeader(HttpHeaders.AUTHORIZATION) context: AuthContextData): UserResponse =
        userService.findById(context.userId).mapTo<UserResponse>()!!

    @GetMapping("/withStaticContext")
    suspend fun findCurrentWithStaticContext(): UserResponse {
        val userId = AuthContext.context.get().userId
        return userService.findById(userId).mapTo<UserResponse>()!!
    }

    @PostMapping
    suspend fun create(
        @RequestBody
        userDTO: UserDTO,
    ): ResponseEntity<Void> = userService.create(userDTO)
        .let { ResponseEntity.created(URI.create("/user/$it")).build() }
}