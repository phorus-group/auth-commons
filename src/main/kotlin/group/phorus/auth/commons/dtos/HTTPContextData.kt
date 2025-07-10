package group.phorus.auth.commons.dtos

import org.springframework.http.HttpMethod
import java.time.Instant

data class HTTPContextData(
    val path: String,
    val method: HttpMethod,
    val headers: Map<String, List<String>>,
    val queryParams: Map<String, List<String>>,
    val remoteAddress: String?,
    val timestamp: Instant = Instant.now(),
    val contentType: String? = null,
    val userAgent: String? = null,
    val origin: String? = null
)