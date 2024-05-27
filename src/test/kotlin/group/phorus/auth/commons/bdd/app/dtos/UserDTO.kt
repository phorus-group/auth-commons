package group.phorus.auth.commons.bdd.app.dtos

import java.util.*

data class UserDTO(
    var name: String? = null,
    var email: String? = null,
    var password: String? = null,
)

data class UserResponse(
    var id: UUID? = null,
    var name: String? = null,
    var email: String? = null,
)
