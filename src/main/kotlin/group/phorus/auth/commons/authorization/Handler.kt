package group.phorus.auth.commons.authorization

enum class HTTPMethod {
    POST, GET, PUT, DELETE
}

enum class HandlerType {
    REST, KAFKA
}

@Target(allowedTargets = [])
annotation class Handler(
    val type: HandlerType = HandlerType.REST,
    val method: HTTPMethod = HTTPMethod.GET,
    val call: String = "",
    val set: String = "",
    val value: String = "",
)
