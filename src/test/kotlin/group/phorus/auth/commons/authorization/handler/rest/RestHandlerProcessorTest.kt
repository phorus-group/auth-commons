package group.phorus.auth.commons.authorization.handler.rest

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import group.phorus.auth.commons.services.impl.AuthorizationReferenceProcessor
import group.phorus.auth.commons.config.AuthorizationProperties
import group.phorus.auth.commons.config.HandlerProperties
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import org.mockito.kotlin.*
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible

@Suppress("UNCHECKED_CAST")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class RestHandlerProcessorTest {

    private lateinit var wireMockServer: WireMockServer
    private val mockProcessor = mock<AuthorizationReferenceProcessor>()
    private val properties = AuthorizationProperties(
        handler = HandlerProperties(timeoutMs = 5000)
    )

    private lateinit var restHandlerProcessor: RestHandlerProcessorProcessor

    @BeforeAll
    fun setupWireMock() {
        wireMockServer = WireMockServer(WireMockConfiguration.options().port(8089))
        wireMockServer.start()

        restHandlerProcessor = RestHandlerProcessorProcessor(properties, mockProcessor)
    }

    @AfterAll
    fun tearDownWireMock() {
        wireMockServer.stop()
    }

    @BeforeEach
    fun setUp() {
        reset(mockProcessor)
        wireMockServer.resetAll()
        clearAllMocks()
    }

    data class TestEntity(val id: String, val organizationId: String)

    @Test
    fun `execute should make successful GET request and return JSON object`() {
        runBlocking {
            val config = RESTHandler(
                call = "http://localhost:8089/api/users/user123/permissions",
                method = HTTPMethod.GET,
                forwardAuth = false,
                saveTo = "permissions"
            )

            val entity = TestEntity("entity123", "org456")
            val handlerContexts = mapOf("previous" to mapOf("data" to "value"))

            whenever(mockProcessor.resolveTemplate(
                template = "http://localhost:8089/api/users/user123/permissions",
                entity = entity,
                extraContexts = handlerContexts
            )).thenReturn("http://localhost:8089/api/users/user123/permissions")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/users/user123/permissions"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("""{"canRead": true, "canWrite": false, "role": "viewer"}""")
                    )
            )

            val result = restHandlerProcessor.execute(config, entity, handlerContexts)

            assertNotNull(result)
            assertTrue(result is Map<*, *>)
            val resultMap = result as Map<String, Any>
            assertEquals(true, resultMap["canRead"])
            assertEquals(false, resultMap["canWrite"])
            assertEquals("viewer", resultMap["role"])
        }
    }

    @Test
    fun `execute should handle all HTTP methods`() {
        runBlocking {
            val entity = TestEntity("entity123", "org456")

            // Test GET
            val getConfig = RESTHandler(call = "http://localhost:8089/api/test", method = HTTPMethod.GET)
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/test", entity, emptyMap())).thenReturn("http://localhost:8089/api/test")
            wireMockServer.stubFor(
                get(urlEqualTo("/api/test"))
                    .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("\"get-result\""))
            )
            val getResult = restHandlerProcessor.execute(getConfig, entity, emptyMap())
            assertEquals("get-result", getResult)

            // Test POST
            val postConfig = RESTHandler(call = "http://localhost:8089/api/test", method = HTTPMethod.POST)
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/test", entity, emptyMap())).thenReturn("http://localhost:8089/api/test")
            wireMockServer.stubFor(
                post(urlEqualTo("/api/test"))
                    .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("\"post-result\""))
            )
            val postResult = restHandlerProcessor.execute(postConfig, entity, emptyMap())
            assertEquals("post-result", postResult)

            // Test PUT
            val putConfig = RESTHandler(call = "http://localhost:8089/api/test", method = HTTPMethod.PUT)
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/test", entity, emptyMap())).thenReturn("http://localhost:8089/api/test")
            wireMockServer.stubFor(
                put(urlEqualTo("/api/test"))
                    .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("\"put-result\""))
            )
            val putResult = restHandlerProcessor.execute(putConfig, entity, emptyMap())
            assertEquals("put-result", putResult)

            // Test DELETE
            val deleteConfig = RESTHandler(call = "http://localhost:8089/api/test", method = HTTPMethod.DELETE)
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/test", entity, emptyMap())).thenReturn("http://localhost:8089/api/test")
            wireMockServer.stubFor(
                delete(urlEqualTo("/api/test"))
                    .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("\"delete-result\""))
            )
            val deleteResult = restHandlerProcessor.execute(deleteConfig, entity, emptyMap())
            assertEquals("delete-result", deleteResult)
        }
    }

    @Test
    fun `execute should forward Authorization header when forwardAuth is true`() {
        runBlocking {
            val config = RESTHandler(
                call = "http://localhost:8089/api/secure",
                method = HTTPMethod.GET,
                forwardAuth = true
            )

            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/secure", null, emptyMap())).thenReturn("http://localhost:8089/api/secure")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/secure"))
                    .withHeader("Authorization", equalTo("Bearer token123"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("""{"success": true}""")
                    )
            )

            // Mock the private function using reflection
            val getAuthHeaderFunction = restHandlerProcessor::class
                .declaredMemberFunctions
                .first { it.name == "getAuthorizationHeader" }
                .apply { isAccessible = true }

            val spiedProcessor = spyk(restHandlerProcessor)
            every {
                getAuthHeaderFunction.call(spiedProcessor)
            } returns "Bearer token123"

            val result = spiedProcessor.execute(config, null, emptyMap())

            assertNotNull(result)
            val resultMap = result as Map<String, Any>
            assertEquals(true, resultMap["success"])

            wireMockServer.verify(
                getRequestedFor(urlEqualTo("/api/secure"))
                    .withHeader("Authorization", equalTo("Bearer token123"))
            )
        }
    }

    @Test
    fun `execute should not forward Authorization header when forwardAuth is false`() {
        runBlocking {
            val config = RESTHandler(
                call = "http://localhost:8089/api/public",
                method = HTTPMethod.GET,
                forwardAuth = false
            )

            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/public", null, emptyMap())).thenReturn("http://localhost:8089/api/public")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/public"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("""{"data": "public"}""")
                    )
            )

            val result = restHandlerProcessor.execute(config, null, emptyMap())

            assertNotNull(result)

            wireMockServer.verify(
                getRequestedFor(urlEqualTo("/api/public"))
                    .withoutHeader("Authorization")
            )
        }
    }

    @Test
    fun `execute should resolve templates with mixed contexts`() {
        runBlocking {
            val config = RESTHandler(
                call = "http://localhost:8089/api/orgs/\${::organizationId}/users/\${auth::userId}/data/\${temp::sessionId}",
                method = HTTPMethod.GET
            )

            val entity = TestEntity("entity123", "org456")
            val handlerContexts = mapOf("temp" to mapOf("sessionId" to "session789"))

            whenever(mockProcessor.resolveTemplate(
                template = "http://localhost:8089/api/orgs/\${::organizationId}/users/\${auth::userId}/data/\${temp::sessionId}",
                entity = entity,
                extraContexts = handlerContexts
            )).thenReturn("http://localhost:8089/api/orgs/org456/users/user123/data/session789")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/orgs/org456/users/user123/data/session789"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("""{"result": "mixed-context"}""")
                    )
            )

            val result = restHandlerProcessor.execute(config, entity, handlerContexts)

            assertNotNull(result)
            val resultMap = result as Map<String, Any>
            assertEquals("mixed-context", resultMap["result"])
        }
    }

    @Test
    fun `execute should return null when template resolution fails`() {
        runBlocking {
            val config = RESTHandler(call = "http://localhost:8089/api/users/invalid-template")
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/users/invalid-template", null, emptyMap())).thenReturn(null)

            val result = restHandlerProcessor.execute(config, null, emptyMap())

            assertNull(result)
            assertEquals(0, wireMockServer.allServeEvents.size)
        }
    }

    @Test
    fun `execute should return null on HTTP errors`() {
        runBlocking {
            val config = RESTHandler(call = "http://localhost:8089/api/error")
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/error", null, emptyMap())).thenReturn("http://localhost:8089/api/error")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/error"))
                    .willReturn(aResponse().withStatus(500).withBody("Internal Server Error"))
            )

            val result = restHandlerProcessor.execute(config, null, emptyMap())

            assertNull(result)
        }
    }

    @Test
    fun `execute should return null on network timeout`() {
        runBlocking {
            val shortTimeoutProperties = AuthorizationProperties(
                handler = HandlerProperties(timeoutMs = 100)
            )
            val shortTimeoutProcessor = RestHandlerProcessorProcessor(shortTimeoutProperties, mockProcessor)

            val config = RESTHandler(call = "http://localhost:8089/api/slow")
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/slow", null, emptyMap())).thenReturn("http://localhost:8089/api/slow")

            wireMockServer.stubFor(
                get(urlEqualTo("/api/slow"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{}")
                            .withFixedDelay(200)
                    )
            )

            val result = shortTimeoutProcessor.execute(config, null, emptyMap())

            assertNull(result)
        }
    }

    @Test
    fun `execute should handle different response types`() {
        runBlocking {
            val stringConfig = RESTHandler(call = "http://localhost:8089/api/response-types")

            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/response-types", null, emptyMap())).thenReturn("http://localhost:8089/api/response-types")
            wireMockServer.stubFor(
                get(urlEqualTo("/api/response-types"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("\"admin\"")
                    )
            )
            val stringResult = restHandlerProcessor.execute(stringConfig, null, emptyMap())
            assertEquals("admin", stringResult)
        }
    }

    @Test
    fun `execute should handle complex nested JSON responses`() {
        runBlocking {
            val config = RESTHandler(call = "http://localhost:8089/api/complex")
            whenever(mockProcessor.resolveTemplate("http://localhost:8089/api/complex", null, emptyMap())).thenReturn("http://localhost:8089/api/complex")

            val complexResponse = """
                {
                    "user": {
                        "id": "user123",
                        "profile": {
                            "name": "John Doe",
                            "permissions": ["read", "write"]
                        }
                    }
                }
            """.trimIndent()

            wireMockServer.stubFor(
                get(urlEqualTo("/api/complex"))
                    .willReturn(
                        aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(complexResponse)
                    )
            )

            val result = restHandlerProcessor.execute(config, null, emptyMap())

            assertNotNull(result)
            assertTrue(result is Map<*, *>)
            val resultMap = result as Map<String, Any>

            val user = resultMap["user"] as Map<String, Any>
            assertEquals("user123", user["id"])
        }
    }
}