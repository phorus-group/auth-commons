package group.phorus.auth.commons.dtos

import java.util.*

data class AuthContextData(
    var userId: UUID,
    var privileges: List<String>,
    val properties: Map<String, String> = emptyMap(),
)