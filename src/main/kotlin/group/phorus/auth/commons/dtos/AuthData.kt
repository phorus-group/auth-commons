package group.phorus.auth.commons.dtos

import java.util.*

data class AuthData(
    var userId: UUID,
    var tokenType: TokenType,
    var jti: String,
    var privileges: List<String>,
    val properties: Map<String, String> = emptyMap(),
)
