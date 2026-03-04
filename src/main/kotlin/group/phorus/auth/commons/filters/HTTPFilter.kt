package group.phorus.auth.commons.filters

import group.phorus.auth.commons.context.HTTPContext
import group.phorus.auth.commons.dtos.HTTPContextData
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.withContext
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.http.HttpHeaders
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange
import java.time.Instant

@AutoConfiguration
class HTTPFilter : CoWebFilter() {
    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        val request = exchange.request

        val contextData = HTTPContextData(
            path = request.path.value(),
            method = request.method,
            headers = buildMap { request.headers.forEach { key, values -> put(key.lowercase(), values) } },
            queryParams = request.queryParams.toMap(),
            remoteAddress = request.remoteAddress?.address?.hostAddress,
            timestamp = Instant.now(),
            contentType = request.headers.contentType?.toString(),
            userAgent = request.headers.getFirst(HttpHeaders.USER_AGENT),
            origin = request.headers.getFirst(HttpHeaders.ORIGIN)
        )

        return withContext(HTTPContext.context.asContextElement(value = contextData)) {
            chain.filter(exchange)
        }
    }
}
