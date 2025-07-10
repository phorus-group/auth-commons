package group.phorus.auth.commons.services.impl

import group.phorus.auth.commons.authorization.context.AuthorizationContextProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.mockito.kotlin.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class AuthorizationReferenceProcessorTest {

    private val mockObjectProcessor = mock<ObjectProcessor>()
    private val mockAuthContextProvider = mock<AuthorizationContextProvider>()
    private val mockHttpRequestContextProvider = mock<AuthorizationContextProvider>()

    private lateinit var processor: AuthorizationReferenceProcessor

    @BeforeEach
    fun setUp() {
        reset(mockObjectProcessor, mockAuthContextProvider, mockHttpRequestContextProvider)

        whenever(mockAuthContextProvider.getContextPrefix()).thenReturn("auth")
        whenever(mockAuthContextProvider.getPriority()).thenReturn(100)

        whenever(mockHttpRequestContextProvider.getContextPrefix()).thenReturn("httpRequest")
        whenever(mockHttpRequestContextProvider.getPriority()).thenReturn(50)

        processor = AuthorizationReferenceProcessor(
            listOf(mockAuthContextProvider, mockHttpRequestContextProvider),
            mockObjectProcessor
        )
    }

    @Test
    fun `resolveValue should delegate to ObjectProcessor for context references`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")

        // When
        val result = processor.resolveValue("auth::userId")

        // Then
        assertEquals("user123", result)
        verify(mockAuthContextProvider).getContextObject()
        verify(mockObjectProcessor).navigateObject(authContext, "userId")
    }

    @Test
    fun `resolveValue should delegate to ObjectProcessor for entity references`() {
        // Given
        val entity = mapOf("id" to "entity123")
        whenever(mockObjectProcessor.navigateObject(entity, "id")).thenReturn("entity123")

        // When
        val result = processor.resolveValue("::id", entity)

        // Then
        assertEquals("entity123", result)
        verify(mockObjectProcessor).navigateObject(entity, "id")
        verifyNoInteractions(mockAuthContextProvider)
    }

    @Test
    fun `resolveValue should return entire object when using empty path`() {
        // Given
        val wholeObject = mapOf("key" to "value", "nested" to mapOf("data" to "result"))
        val extraContexts = mapOf("something" to wholeObject)

        whenever(mockObjectProcessor.navigateObject(wholeObject, "")).thenReturn(wholeObject)

        // When
        val result = processor.resolveValue("something::", null, extraContexts)

        // Then
        assertEquals(wholeObject, result)
        verify(mockObjectProcessor).navigateObject(wholeObject, "")
    }

    @Test
    fun `resolveValue should return entire object`() {
        // Given
        val extraContext = mapOf("key" to "value", "nested" to mapOf("data" to "result"))
        val extraContexts = mapOf("custom" to extraContext)
        whenever(mockObjectProcessor.navigateObject(extraContext, "nested")).thenReturn(mapOf("data" to "result"))

        // When
        val result = processor.resolveValue("custom::nested", null, extraContexts)

        // Then
        assertEquals(mapOf("data" to "result"), result)
        verify(mockObjectProcessor).navigateObject(extraContext, "nested")
        verifyNoInteractions(mockAuthContextProvider)
    }

    @Test
    fun `resolveValue should use extra contexts when provided`() {
        // Given
        val extraContext = mapOf("key" to "value", "nested" to mapOf("data" to "result"))
        val extraContexts = mapOf("custom" to extraContext)
        whenever(mockObjectProcessor.navigateObject(extraContext, "nested/data")).thenReturn("result")

        // When
        val result = processor.resolveValue("custom::nested/data", null, extraContexts)

        // Then
        assertEquals("result", result)
        verify(mockObjectProcessor).navigateObject(extraContext, "nested/data")
        verifyNoInteractions(mockAuthContextProvider)
    }

    @Test
    fun `resolveValue should prioritize extra contexts over regular contexts`() {
        // Given
        val regularContext = mapOf("userId" to "regular-user")
        val extraContext = mapOf("userId" to "extra-user")
        val extraContexts = mapOf("auth" to extraContext)

        whenever(mockAuthContextProvider.getContextObject()).thenReturn(regularContext)
        whenever(mockObjectProcessor.navigateObject(extraContext, "userId")).thenReturn("extra-user")

        // When
        val result = processor.resolveValue("auth::userId", null, extraContexts)

        // Then
        assertEquals("extra-user", result)
        verify(mockObjectProcessor).navigateObject(extraContext, "userId")
        verifyNoInteractions(mockAuthContextProvider) // Should not call regular context
    }

    @Test
    fun `resolveValue should parse reference with special characters in bracket keys`() {
        // Given
        val authContext = mapOf("settings" to "value")
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "settings[api-endpoint]/url")).thenReturn("http://api.com")

        // When
        val result = processor.resolveValue("auth::settings[api-endpoint]/url")

        // Then
        assertEquals("http://api.com", result)
        verify(mockObjectProcessor).navigateObject(authContext, "settings[api-endpoint]/url")
    }

    @Test
    fun `resolveValue should return null for invalid reference format`() {
        // When
        val result = processor.resolveValue("invalid-reference")

        // Then
        assertNull(result)
        verifyNoInteractions(mockObjectProcessor, mockAuthContextProvider)
    }

    @Test
    fun `resolveValue should return null for unknown context prefix`() {
        // When
        val result = processor.resolveValue("unknown::property")

        // Then
        assertNull(result)
        verifyNoInteractions(mockObjectProcessor)
    }

    @Test
    fun `resolveValue should return null when context provider returns null`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(null)

        // When
        val result = processor.resolveValue("auth::userId")

        // Then
        assertNull(result)
        verifyNoInteractions(mockObjectProcessor)
    }

    @Test
    fun `resolveValue should return null for entity reference without entity`() {
        // When
        val result = processor.resolveValue("::id")

        // Then
        assertNull(result)
        verifyNoInteractions(mockObjectProcessor)
    }

    @Test
    fun `exists should return true when resolveValue returns non-null`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")

        // When
        val result = processor.exists("auth::userId")

        // Then
        assertTrue(result)
    }

    @Test
    fun `exists should return false when resolveValue returns null`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(null)

        // When
        val result = processor.exists("auth::userId")

        // Then
        assertFalse(result)
    }

    @Test
    fun `exists should work with extra contexts`() {
        // Given
        val extraContext = mapOf("data" to "value")
        val extraContexts = mapOf("temp" to extraContext)
        whenever(mockObjectProcessor.navigateObject(extraContext, "data")).thenReturn("value")

        // When
        val result = processor.exists("temp::data", null, extraContexts)

        // Then
        assertTrue(result)
    }

    @Test
    fun `existsAny should return true when any reference exists`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "nonexistent")).thenReturn(null)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")

        // When
        val result = processor.existsAny(arrayOf("auth::nonexistent", "auth::userId"))

        // Then
        assertTrue(result)
    }

    @Test
    fun `existsAny should work with mixed regular and extra contexts`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        val extraContext = mapOf("flag" to true)
        val extraContexts = mapOf("temp" to extraContext)

        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "nonexistent")).thenReturn(null)
        whenever(mockObjectProcessor.navigateObject(extraContext, "flag")).thenReturn(true)

        // When
        val result = processor.existsAny(arrayOf("auth::nonexistent", "temp::flag"), null, extraContexts)

        // Then
        assertTrue(result)
    }

    @Test
    fun `existsAny should handle exceptions gracefully`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenThrow(RuntimeException("Test error"))

        // When
        val result = processor.existsAny(arrayOf("auth::userId"))

        // Then
        assertFalse(result)
    }

    @Test
    fun `compareValues should delegate to ObjectProcessor`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        val entity = mapOf("ownerId" to "user123")

        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")
        whenever(mockObjectProcessor.navigateObject(entity, "ownerId")).thenReturn("user123")
        whenever(mockObjectProcessor.compareValues("user123", "user123")).thenReturn(true)

        // When
        val result = processor.compareValues("auth::userId", "::ownerId", entity)

        // Then
        assertTrue(result)
        verify(mockObjectProcessor).compareValues("user123", "user123")
    }

    @Test
    fun `compareValues should work with extra contexts`() {
        // Given
        val extraContext1 = mapOf("value" to "test")
        val extraContext2 = mapOf("value" to "test")
        val extraContexts = mapOf("temp1" to extraContext1, "temp2" to extraContext2)

        whenever(mockObjectProcessor.navigateObject(extraContext1, "value")).thenReturn("test")
        whenever(mockObjectProcessor.navigateObject(extraContext2, "value")).thenReturn("test")
        whenever(mockObjectProcessor.compareValues("test", "test")).thenReturn(true)

        // When
        val result = processor.compareValues("temp1::value", "temp2::value", null, extraContexts)

        // Then
        assertTrue(result)
        verify(mockObjectProcessor).compareValues("test", "test")
    }

    @Test
    fun `compareValues should handle exceptions gracefully`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenThrow(RuntimeException("Test error"))

        // When
        val result = processor.compareValues("auth::userId", "::ownerId", null)

        // Then
        assertFalse(result)
    }

    @Test
    fun `resolveTemplate should resolve variables and delegate to resolveValue`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        val entity = mapOf("id" to "entity123")

        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")
        whenever(mockObjectProcessor.navigateObject(entity, "id")).thenReturn("entity123")

        // When
        val result = processor.resolveTemplate("/api/users/\${auth::userId}/entities/\${::id}", entity)

        // Then
        assertEquals("/api/users/user123/entities/entity123", result)
    }

    @Test
    fun `resolveTemplate should support dynamic value field templates for authorization`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        val entity = mapOf("id" to "entity456", "organizationId" to "org789")
        val extraContext = mapOf("sessionId" to "session999")
        val extraContexts = mapOf("temp" to extraContext)

        // Setup mocks for all context types
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user123")
        whenever(mockObjectProcessor.navigateObject(entity, "organizationId")).thenReturn("org789")
        whenever(mockObjectProcessor.navigateObject(extraContext, "sessionId")).thenReturn("session999")

        // When - resolve a dynamic value field template like what would be used in Authorize annotation
        val result = processor.resolveTemplate(
            template = "response::user/\${auth::userId}/permissions/org-\${::organizationId}/session-\${temp::sessionId}",
            entity = entity,
            extraContexts = extraContexts
        )

        // Then
        assertEquals("response::user/user123/permissions/org-org789/session-session999", result)
        verify(mockObjectProcessor).navigateObject(authContext, "userId")
        verify(mockObjectProcessor).navigateObject(entity, "organizationId")
        verify(mockObjectProcessor).navigateObject(extraContext, "sessionId")
    }

    @Test
    fun `resolveTemplate should work with extra contexts`() {
        // Given
        val extraContext = mapOf("sessionId" to "session123", "apiKey" to "key456")
        val extraContexts = mapOf("temp" to extraContext)

        whenever(mockObjectProcessor.navigateObject(extraContext, "sessionId")).thenReturn("session123")
        whenever(mockObjectProcessor.navigateObject(extraContext, "apiKey")).thenReturn("key456")

        // When
        val result = processor.resolveTemplate("/api/session/\${temp::sessionId}/auth/\${temp::apiKey}", null, extraContexts)

        // Then
        assertEquals("/api/session/session123/auth/key456", result)
    }

    @Test
    fun `resolveTemplate should work with mixed entity, regular contexts, and extra contexts`() {
        // Given
        val entity = mapOf("id" to "entity123", "organizationId" to "org456")
        val authContext = mapOf("userId" to "user789", "privileges" to setOf("admin"))
        val extraContext = mapOf("sessionId" to "session999", "apiKey" to "key777")
        val extraContexts = mapOf("temp" to extraContext)

        // Setup mocks for regular contexts
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)
        whenever(mockObjectProcessor.navigateObject(authContext, "userId")).thenReturn("user789")

        // Setup mocks for entity
        whenever(mockObjectProcessor.navigateObject(entity, "id")).thenReturn("entity123")
        whenever(mockObjectProcessor.navigateObject(entity, "organizationId")).thenReturn("org456")

        // Setup mocks for extra contexts
        whenever(mockObjectProcessor.navigateObject(extraContext, "sessionId")).thenReturn("session999")
        whenever(mockObjectProcessor.navigateObject(extraContext, "apiKey")).thenReturn("key777")

        // When - template with all three types of contexts
        val result = processor.resolveTemplate(
            template = "/api/orgs/\${::organizationId}/users/\${auth::userId}/session/\${temp::sessionId}/entity/\${::id}/auth/\${temp::apiKey}",
            entity = entity,
            extraContexts = extraContexts
        )

        // Then
        assertEquals("/api/orgs/org456/users/user789/session/session999/entity/entity123/auth/key777", result)

        // Verify all navigation calls were made
        verify(mockObjectProcessor).navigateObject(entity, "organizationId")
        verify(mockObjectProcessor).navigateObject(entity, "id")
        verify(mockObjectProcessor).navigateObject(authContext, "userId")
        verify(mockObjectProcessor).navigateObject(extraContext, "sessionId")
        verify(mockObjectProcessor).navigateObject(extraContext, "apiKey")
    }

    @Test
    fun `resolveTemplate should return null when any variable fails to resolve`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(null)

        // When
        val result = processor.resolveTemplate("/api/users/\${auth::userId}/data")

        // Then
        assertNull(result)
    }

    @Test
    fun `resolveTemplate should handle literal values`() {
        // When
        val result = processor.resolveTemplate("static-\${literal}-value")

        // Then
        assertEquals("static-literal-value", result)
    }

    @Test
    fun `resolveTemplate should handle exceptions gracefully`() {
        // Given
        whenever(mockAuthContextProvider.getContextObject()).thenThrow(RuntimeException("Test error"))

        // When
        val result = processor.resolveTemplate("\${auth::userId}")

        // Then
        assertNull(result)
    }

    @Test
    fun `navigateObject should delegate to ObjectProcessor`() {
        // Given
        val obj = mapOf("nested" to mapOf("value" to "result"))
        whenever(mockObjectProcessor.navigateObject(obj, "nested/value")).thenReturn("result")

        // When
        val result = processor.navigateObject(obj, "nested/value")

        // Then
        assertEquals("result", result)
        verify(mockObjectProcessor).navigateObject(obj, "nested/value")
    }

    @Test
    fun `getAvailableContexts should return only available context prefixes`() {
        // When
        val result = processor.getAvailableContexts()

        // Then
        assertEquals(setOf("auth", "httpRequest"), result)
    }

    @Test
    fun `getContextObject should return context for valid prefix`() {
        // Given
        val authContext = mapOf("userId" to "user123")
        whenever(mockAuthContextProvider.getContextObject()).thenReturn(authContext)

        // When
        val result = processor.getContextObject("auth")

        // Then
        assertEquals(authContext, result)
    }

    @Test
    fun `getContextObject should return null for invalid prefix`() {
        // When
        val result = processor.getContextObject("invalid")

        // Then
        assertNull(result)
    }

    @Test
    fun `context registry should respect provider priorities with duplicate prefixes`() {
        // Given - setup two providers with same prefix but different priorities
        val highPriorityProvider = mock<AuthorizationContextProvider>()
        val lowPriorityProvider = mock<AuthorizationContextProvider>()

        whenever(highPriorityProvider.getContextPrefix()).thenReturn("same")
        whenever(highPriorityProvider.getPriority()).thenReturn(100)
        whenever(highPriorityProvider.getContextObject()).thenReturn("high-priority")

        whenever(lowPriorityProvider.getContextPrefix()).thenReturn("same")
        whenever(lowPriorityProvider.getPriority()).thenReturn(50)
        whenever(lowPriorityProvider.getContextObject()).thenReturn("low-priority")

        val processorWithDuplicates = AuthorizationReferenceProcessor(
            listOf(lowPriorityProvider, highPriorityProvider), // Order doesn't matter
            mockObjectProcessor
        )

        // When
        val contextObject = processorWithDuplicates.getContextObject("same")
        val availableContexts = processorWithDuplicates.getAvailableContexts()

        // Then
        assertEquals("high-priority", contextObject) // Should use highest priority
        assertEquals(setOf("same"), availableContexts) // Should only have one entry
        verify(highPriorityProvider).getContextObject()
        verify(lowPriorityProvider, never()).getContextObject()
    }
}