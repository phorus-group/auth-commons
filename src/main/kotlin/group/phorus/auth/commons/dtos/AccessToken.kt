package group.phorus.auth.commons.dtos

data class AccessToken(
    val token: String,
    val privileges: List<String>,
)