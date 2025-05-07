package group.phorus.auth.commons.bdd.app.services.impl

import group.phorus.auth.commons.bdd.app.dtos.UserDTO
import group.phorus.auth.commons.bdd.app.model.User
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.auth.commons.bdd.app.services.UserService
import group.phorus.exception.handling.Unauthorized
import group.phorus.mapper.mapping.MappingFallback
import group.phorus.mapper.mapping.extensions.mapTo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
import org.springframework.stereotype.Service
import java.util.*

@Service
class UserServiceImpl(
    private val encoder: SCryptPasswordEncoder,
    private val userRepository: UserRepository,
) : UserService {
    override suspend fun create(userDTO: UserDTO): UUID = userDTO.mapTo<User>(functionMappings = mapOf(
        UserDTO::password to ({ password: String -> encoder.encode(password) } to (User::passwordHash to MappingFallback.NULL))
    ))!!.let { userRepository.save(it) }.id!!

    override suspend fun findById(id: UUID): User = withContext(Dispatchers.IO) {
        userRepository.findById(id).orElseThrow {
            Unauthorized("User not found with id: $id")
        }
    }

    override suspend fun findByEmail(email: String): User = withContext(Dispatchers.IO) {
        userRepository.findByEmail(email).orElseThrow {
            Unauthorized("User not found with email: $email")
        }
    }
}