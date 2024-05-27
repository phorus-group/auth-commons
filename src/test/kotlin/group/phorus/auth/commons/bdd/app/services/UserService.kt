package group.phorus.auth.commons.bdd.app.services

import group.phorus.auth.commons.bdd.app.dtos.UserDTO
import group.phorus.auth.commons.bdd.app.model.User
import java.util.*

interface UserService {
    suspend fun create(userDTO: UserDTO): UUID
    suspend fun findById(id: UUID): User
    suspend fun findByEmail(email: String): User
}
