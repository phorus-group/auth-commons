package group.phorus.auth.commons.services.impl

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.TreeMap

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class ObjectProcessorTest {

    private val objectProcessor = ObjectProcessor()

    // Test data classes
    data class TestUser(
        val id: String,
        val name: String,
        val email: String,
        val profile: TestProfile,
        val addresses: List<TestAddress>,
        val settings: Map<String, String>,
        val privileges: Set<String>,
        val tags: Array<String>,
        val metadata: TestMetadata?
    )

    data class TestProfile(
        val firstName: String,
        val lastName: String,
        val contact: TestContact
    )

    data class TestContact(
        val phone: String,
        val email: String
    )

    data class TestAddress(
        val type: String,
        val street: String,
        val city: String,
        val coordinates: TestCoordinates
    )

    data class TestCoordinates(
        val latitude: Double,
        val longitude: Double
    )

    data class TestMetadata(
        val createdBy: String,
        val version: Int
    )

    private fun createTestUser(): TestUser {
        return TestUser(
            id = "user123",
            name = "John Doe",
            email = "john.doe@example.com",
            profile = TestProfile(
                firstName = "John",
                lastName = "Doe",
                contact = TestContact(
                    phone = "+1234567890",
                    email = "john.contact@example.com"
                )
            ),
            addresses = listOf(
                TestAddress(
                    type = "home",
                    street = "123 Main St",
                    city = "New York",
                    coordinates = TestCoordinates(40.7128, -74.0060)
                ),
                TestAddress(
                    type = "work",
                    street = "456 Office Ave",
                    city = "Boston",
                    coordinates = TestCoordinates(42.3601, -71.0589)
                )
            ),
            settings = mapOf(
                "theme" to "dark",
                "language" to "en",
                "notifications" to "enabled"
            ),
            privileges = setOf("admin", "user", "manager"),
            tags = arrayOf("premium", "active", "verified"),
            metadata = TestMetadata(
                createdBy = "system",
                version = 1
            )
        )
    }

    /**
     * Creates a LinkedHashMap similar to what REST APIs return
     */
    private fun createRestApiResponse(): LinkedHashMap<String, Any?> {
        return linkedMapOf(
            "userId" to "user123",
            "canAccess" to true,
            "permissions" to linkedMapOf(
                "read" to true,
                "write" to false,
                "admin" to true
            ),
            "user" to linkedMapOf(
                "id" to "user123",
                "name" to "John Doe",
                "profile" to linkedMapOf(
                    "firstName" to "John",
                    "lastName" to "Doe",
                    "contact" to linkedMapOf(
                        "email" to "john@example.com",
                        "phone" to "+1234567890"
                    )
                )
            ),
            "roles" to listOf("admin", "user", "manager"),
            "tags" to arrayOf("premium", "verified"),
            "settings" to linkedMapOf(
                "theme" to "dark",
                "notifications" to linkedMapOf(
                    "email" to true,
                    "push" to false
                )
            ),
            "metadata" to null
        )
    }

    @Test
    fun `navigateObject should return object itself for empty path`() {
        // Given
        val user = createTestUser()

        // When
        val result = objectProcessor.navigateObject(user, "")

        // Then
        assertEquals(user, result)
    }

    @Test
    fun `navigateObject should return entire object`() {
        // Given
        val user = createTestUser()

        // When
        val result = objectProcessor.navigateObject(user, "profile")

        // Then
        assertEquals(user.profile, result)
    }

    @Test
    fun `navigateObject should access simple properties`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("user123", objectProcessor.navigateObject(user, "id"))
        assertEquals("John Doe", objectProcessor.navigateObject(user, "name"))
        assertEquals("john.doe@example.com", objectProcessor.navigateObject(user, "email"))
    }

    @Test
    fun `navigateObject should access nested object properties`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("John", objectProcessor.navigateObject(user, "profile/firstName"))
        assertEquals("Doe", objectProcessor.navigateObject(user, "profile/lastName"))
        assertEquals("+1234567890", objectProcessor.navigateObject(user, "profile/contact/phone"))
        assertEquals("john.contact@example.com", objectProcessor.navigateObject(user, "profile/contact/email"))
    }

    @Test
    fun `navigateObject should access array elements by index`() {
        // Given
        val user = createTestUser()

        // When & Then
        @Suppress("UNCHECKED_CAST")
        val addresses = objectProcessor.navigateObject(user, "addresses") as List<TestAddress>
        assertEquals(2, addresses.size)

        val firstAddress = objectProcessor.navigateObject(user, "addresses[0]") as TestAddress
        assertEquals("home", firstAddress.type)
        assertEquals("123 Main St", firstAddress.street)

        val secondAddress = objectProcessor.navigateObject(user, "addresses[1]") as TestAddress
        assertEquals("work", secondAddress.type)
        assertEquals("456 Office Ave", secondAddress.street)
    }

    @Test
    fun `navigateObject should access nested properties in array elements`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("home", objectProcessor.navigateObject(user, "addresses[0]/type"))
        assertEquals("New York", objectProcessor.navigateObject(user, "addresses[0]/city"))
        assertEquals(40.7128, objectProcessor.navigateObject(user, "addresses[0]/coordinates/latitude"))
        assertEquals(-74.0060, objectProcessor.navigateObject(user, "addresses[0]/coordinates/longitude"))
    }

    @Test
    fun `navigateObject should access map values by key`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("dark", objectProcessor.navigateObject(user, "settings[theme]"))
        assertEquals("en", objectProcessor.navigateObject(user, "settings[language]"))
        assertEquals("enabled", objectProcessor.navigateObject(user, "settings[notifications]"))
    }

    @Test
    fun `navigateObject should check collection membership`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("admin", objectProcessor.navigateObject(user, "privileges/admin"))
        assertEquals("manager", objectProcessor.navigateObject(user, "privileges/manager"))
        assertNull(objectProcessor.navigateObject(user, "privileges/nonexistent"))
    }

    @Test
    fun `navigateObject should check array membership`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("premium", objectProcessor.navigateObject(user, "tags/premium"))
        assertEquals("verified", objectProcessor.navigateObject(user, "tags/verified"))
        assertNull(objectProcessor.navigateObject(user, "tags/nonexistent"))
    }

    @Test
    fun `navigateObject should handle null properties gracefully`() {
        // Given
        val user = createTestUser().copy(metadata = null)

        // When & Then
        assertNull(objectProcessor.navigateObject(user, "metadata"))
        assertNull(objectProcessor.navigateObject(user, "metadata/createdBy"))
        assertNull(objectProcessor.navigateObject(user, "nonexistent"))
        assertNull(objectProcessor.navigateObject(user, "profile/nonexistent"))
    }

    @Test
    fun `navigateObject should handle invalid array indices`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertNull(objectProcessor.navigateObject(user, "addresses[10]"))
        assertNull(objectProcessor.navigateObject(user, "addresses[-1]"))
        assertNull(objectProcessor.navigateObject(user, "addresses[-1]/createdBy"))
        assertNull(objectProcessor.navigateObject(user, "addresses[invalid]"))
        assertNull(objectProcessor.navigateObject(user, "addresses[invalid]/createdBy"))
    }

    @Test
    fun `navigateObject should handle invalid map keys`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertNull(objectProcessor.navigateObject(user, "settings[nonexistent]"))
        assertNull(objectProcessor.navigateObject(user, "settings[nonexistent]/createdBy"))
    }

    // LinkedHashMap tests (REST API responses)
    @Test
    fun `navigateObject should access LinkedHashMap properties directly`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertEquals("user123", objectProcessor.navigateObject(response, "userId"))
        assertEquals(true, objectProcessor.navigateObject(response, "canAccess"))
    }

    @Test
    fun `navigateObject should access nested LinkedHashMap properties`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertEquals(true, objectProcessor.navigateObject(response, "permissions/read"))
        assertEquals(false, objectProcessor.navigateObject(response, "permissions/write"))
        assertEquals(true, objectProcessor.navigateObject(response, "permissions/admin"))
    }

    @Test
    fun `navigateObject should access deeply nested LinkedHashMap properties`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertEquals("user123", objectProcessor.navigateObject(response, "user/id"))
        assertEquals("John Doe", objectProcessor.navigateObject(response, "user/name"))
        assertEquals("John", objectProcessor.navigateObject(response, "user/profile/firstName"))
        assertEquals("Doe", objectProcessor.navigateObject(response, "user/profile/lastName"))
        assertEquals("john@example.com", objectProcessor.navigateObject(response, "user/profile/contact/email"))
        assertEquals("+1234567890", objectProcessor.navigateObject(response, "user/profile/contact/phone"))
    }

    @Test
    fun `navigateObject should access nested LinkedHashMap with bracket notation`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertEquals("dark", objectProcessor.navigateObject(response, "settings[theme]"))
        assertEquals(true, objectProcessor.navigateObject(response, "settings[notifications]/email"))
        assertEquals(false, objectProcessor.navigateObject(response, "settings[notifications]/push"))
    }

    @Test
    fun `navigateObject should check collection membership in LinkedHashMap`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertEquals("admin", objectProcessor.navigateObject(response, "roles/admin"))
        assertEquals("user", objectProcessor.navigateObject(response, "roles/user"))
        assertEquals("premium", objectProcessor.navigateObject(response, "tags/premium"))
        assertNull(objectProcessor.navigateObject(response, "roles/nonexistent"))
    }

    @Test
    fun `navigateObject should handle null values in LinkedHashMap`() {
        // Given
        val response = createRestApiResponse()

        // When & Then
        assertNull(objectProcessor.navigateObject(response, "metadata"))
        assertNull(objectProcessor.navigateObject(response, "metadata/createdBy"))
        assertNull(objectProcessor.navigateObject(response, "nonexistent"))
    }

    @Test
    fun `navigateObject should handle mixed objects and LinkedHashMap`() {
        // Given - Create a regular object that contains a LinkedHashMap
        val restApiData = createRestApiResponse()
        val mixedData = TestUser(
            id = "mixed123",
            name = "Mixed User",
            email = "mixed@example.com",
            profile = TestProfile(
                firstName = "Mixed",
                lastName = "User",
                contact = TestContact("555-0123", "contact@example.com")
            ),
            addresses = listOf(),
            settings = mapOf("theme" to "dark", "language" to "en"), // Proper Map<String, String>
            privileges = setOf(),
            tags = arrayOf(),
            metadata = null
        )

        // When & Then - Navigate REST API response directly
        assertEquals("user123", objectProcessor.navigateObject(restApiData, "userId"))
        assertEquals(true, objectProcessor.navigateObject(restApiData, "canAccess"))
        assertEquals("John", objectProcessor.navigateObject(restApiData, "user/profile/firstName"))
        assertEquals("dark", objectProcessor.navigateObject(restApiData, "settings[theme]"))

        // And navigate regular object
        assertEquals("mixed123", objectProcessor.navigateObject(mixedData, "id"))
        assertEquals("dark", objectProcessor.navigateObject(mixedData, "settings[theme]"))
        assertEquals("Mixed", objectProcessor.navigateObject(mixedData, "profile/firstName"))
    }

    @Test
    fun `getObjectProperty should access LinkedHashMap properties`() {
        // Given - Create actual LinkedHashMap
        val map = LinkedHashMap<String, Any>().apply {
            put("key1", "value1")
            put("key2", "value2")
            put("nested", LinkedHashMap<String, Any>().apply {
                put("inner", "innerValue")
            })
        }

        // When & Then
        assertEquals("value1", objectProcessor.getObjectProperty(map, "key1"))
        assertEquals("value2", objectProcessor.getObjectProperty(map, "key2"))
        assertNotNull(objectProcessor.getObjectProperty(map, "nested"))
        assertNull(objectProcessor.getObjectProperty(map, "nonexistent"))
    }

    @Test
    fun `getObjectProperty should work with different Map types`() {
        // Given - Create actual Map instances
        val hashMap = HashMap<String, String>().apply { put("key", "hashMapValue") }
        val treeMap = TreeMap<String, String>().apply { put("key", "treeMapValue") }
        val linkedMap = LinkedHashMap<String, String>().apply { put("key", "linkedMapValue") }

        // When & Then
        assertEquals("hashMapValue", objectProcessor.getObjectProperty(hashMap, "key"))
        assertEquals("treeMapValue", objectProcessor.getObjectProperty(treeMap, "key"))
        assertEquals("linkedMapValue", objectProcessor.getObjectProperty(linkedMap, "key"))
    }

    @Test
    fun `parsePath should parse simple property paths`() {
        // When
        val segments = objectProcessor.parsePath("name")

        // Then
        assertEquals(1, segments.size)
        assertEquals("name", segments[0].property)
        assertNull(segments[0].bracketKey)
        assertFalse(segments[0].isBracketNotation)
    }

    @Test
    fun `parsePath should parse nested property paths`() {
        // When
        val segments = objectProcessor.parsePath("profile/contact/email")

        // Then
        assertEquals(3, segments.size)
        assertEquals("profile", segments[0].property)
        assertEquals("contact", segments[1].property)
        assertEquals("email", segments[2].property)
        segments.forEach {
            assertNull(it.bracketKey)
            assertFalse(it.isBracketNotation)
        }
    }

    @Test
    fun `parsePath should parse bracket notation`() {
        // When
        val segments = objectProcessor.parsePath("addresses[0]/settings[theme]")

        // Then
        assertEquals(2, segments.size)

        assertEquals("addresses", segments[0].property)
        assertEquals("0", segments[0].bracketKey)
        assertTrue(segments[0].isBracketNotation)

        assertEquals("settings", segments[1].property)
        assertEquals("theme", segments[1].bracketKey)
        assertTrue(segments[1].isBracketNotation)
    }

    @Test
    fun `parsePath should parse mixed notation`() {
        // When
        val segments = objectProcessor.parsePath("profile/addresses[0]/coordinates/latitude")

        // Then
        assertEquals(4, segments.size)

        assertEquals("profile", segments[0].property)
        assertFalse(segments[0].isBracketNotation)

        assertEquals("addresses", segments[1].property)
        assertEquals("0", segments[1].bracketKey)
        assertTrue(segments[1].isBracketNotation)

        assertEquals("coordinates", segments[2].property)
        assertFalse(segments[2].isBracketNotation)

        assertEquals("latitude", segments[3].property)
        assertFalse(segments[3].isBracketNotation)
    }

    @Test
    fun `accessByKeyOrIndex should access map by key`() {
        // Given
        val map = mapOf("key1" to "value1", "key2" to "value2")

        // When & Then
        assertEquals("value1", objectProcessor.accessByKeyOrIndex(map, "key1"))
        assertEquals("value2", objectProcessor.accessByKeyOrIndex(map, "key2"))
        assertNull(objectProcessor.accessByKeyOrIndex(map, "nonexistent"))
    }

    @Test
    fun `accessByKeyOrIndex should access list by index`() {
        // Given
        val list = listOf("item0", "item1", "item2")

        // When & Then
        assertEquals("item0", objectProcessor.accessByKeyOrIndex(list, "0"))
        assertEquals("item1", objectProcessor.accessByKeyOrIndex(list, "1"))
        assertEquals("item2", objectProcessor.accessByKeyOrIndex(list, "2"))
        assertNull(objectProcessor.accessByKeyOrIndex(list, "10"))
        assertNull(objectProcessor.accessByKeyOrIndex(list, "invalid"))
    }

    @Test
    fun `accessByKeyOrIndex should access array by index`() {
        // Given
        val array = arrayOf("item0", "item1", "item2")

        // When & Then
        assertEquals("item0", objectProcessor.accessByKeyOrIndex(array, "0"))
        assertEquals("item1", objectProcessor.accessByKeyOrIndex(array, "1"))
        assertEquals("item2", objectProcessor.accessByKeyOrIndex(array, "2"))
        assertNull(objectProcessor.accessByKeyOrIndex(array, "10"))
        assertNull(objectProcessor.accessByKeyOrIndex(array, "invalid"))
    }

    @Test
    fun `accessByKeyOrIndex should handle invalid collection types`() {
        // Given
        val notACollection = "just a string"

        // When & Then
        assertNull(objectProcessor.accessByKeyOrIndex(notACollection, "0"))
    }

    @Test
    fun `checkCollectionMembership should check list membership`() {
        // Given
        val list = listOf("item1", "item2", "item3")

        // When & Then
        assertTrue(objectProcessor.checkCollectionMembership(list, "item1"))
        assertTrue(objectProcessor.checkCollectionMembership(list, "item2"))
        assertFalse(objectProcessor.checkCollectionMembership(list, "nonexistent"))
    }

    @Test
    fun `checkCollectionMembership should check set membership`() {
        // Given
        val set = setOf("admin", "user", "manager")

        // When & Then
        assertTrue(objectProcessor.checkCollectionMembership(set, "admin"))
        assertTrue(objectProcessor.checkCollectionMembership(set, "user"))
        assertFalse(objectProcessor.checkCollectionMembership(set, "nonexistent"))
    }

    @Test
    fun `checkCollectionMembership should check array membership`() {
        // Given
        val array = arrayOf("tag1", "tag2", "tag3")

        // When & Then
        assertTrue(objectProcessor.checkCollectionMembership(array, "tag1"))
        assertTrue(objectProcessor.checkCollectionMembership(array, "tag2"))
        assertFalse(objectProcessor.checkCollectionMembership(array, "nonexistent"))
    }

    @Test
    fun `checkCollectionMembership should handle non-collections`() {
        // Given
        val notACollection = "just a string"

        // When & Then
        assertFalse(objectProcessor.checkCollectionMembership(notACollection, "string"))
    }

    @Test
    fun `getObjectProperty should access kotlin properties`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertEquals("user123", objectProcessor.getObjectProperty(user, "id"))
        assertEquals("John Doe", objectProcessor.getObjectProperty(user, "name"))
        assertNotNull(objectProcessor.getObjectProperty(user, "profile"))
    }

    @Test
    fun `getObjectProperty should handle nonexistent properties`() {
        // Given
        val user = createTestUser()

        // When & Then
        assertNull(objectProcessor.getObjectProperty(user, "nonexistent"))
        assertNull(objectProcessor.getObjectProperty(user, "invalid"))
    }

    @Test
    fun `compareValues should compare same type values`() {
        // When & Then
        assertTrue(objectProcessor.compareValues("test", "test"))
        assertTrue(objectProcessor.compareValues(123, 123))
        assertTrue(objectProcessor.compareValues(true, true))
        assertFalse(objectProcessor.compareValues("test1", "test2"))
        assertFalse(objectProcessor.compareValues(123, 456))
    }

    @Test
    fun `compareValues should compare null values`() {
        // When & Then
        assertTrue(objectProcessor.compareValues(null, null))
        assertFalse(objectProcessor.compareValues(null, "test"))
        assertFalse(objectProcessor.compareValues("test", null))
    }

    @Test
    fun `compareValues should compare different numeric types`() {
        // When & Then
        assertTrue(objectProcessor.compareValues(123, 123.0))
        assertTrue(objectProcessor.compareValues(123.0f, 123.0))
        assertFalse(objectProcessor.compareValues(123, 456.0))
    }

    @Test
    fun `compareValues should fall back to string comparison for different types`() {
        // When & Then
        assertTrue(objectProcessor.compareValues(123, "123"))
        assertTrue(objectProcessor.compareValues(true, "true"))
        assertFalse(objectProcessor.compareValues(123, "456"))
    }

    @Test
    fun `compareValues should handle collections of same type`() {
        // When & Then
        assertTrue(objectProcessor.compareValues(listOf(1, 2, 3), listOf(1, 2, 3)))
        assertTrue(objectProcessor.compareValues(setOf("a", "b"), setOf("a", "b")))
        assertFalse(objectProcessor.compareValues(listOf(1, 2, 3), listOf(3, 2, 1)))
    }

    @Test
    fun `compareValues should handle maps`() {
        // When & Then
        assertTrue(objectProcessor.compareValues(
            mapOf("key" to "value"),
            mapOf("key" to "value")
        ))
        assertFalse(objectProcessor.compareValues(
            mapOf("key1" to "value"),
            mapOf("key2" to "value")
        ))
    }

    @Test
    fun `navigateObject should handle complex scenarios`() {
        // Given
        val user = createTestUser()

        // When & Then - Complex navigation scenarios
        assertEquals(40.7128, objectProcessor.navigateObject(user, "addresses[0]/coordinates/latitude"))
        assertEquals("work", objectProcessor.navigateObject(user, "addresses[1]/type"))
        assertEquals("dark", objectProcessor.navigateObject(user, "settings[theme]"))
        assertEquals("system", objectProcessor.navigateObject(user, "metadata/createdBy"))
        assertEquals("admin", objectProcessor.navigateObject(user, "privileges/admin"))
        assertEquals("premium", objectProcessor.navigateObject(user, "tags/premium"))
    }

    @Test
    fun `navigateObject should handle edge cases gracefully`() {
        // Given
        val user = createTestUser()

        // When & Then - Edge cases that should return null
        assertNull(objectProcessor.navigateObject(user, "addresses[0]/nonexistent"))
        assertNull(objectProcessor.navigateObject(user, "settings[nonexistent]/property"))
        assertNull(objectProcessor.navigateObject(user, "nonexistent[0]"))
        assertNull(objectProcessor.navigateObject(user, "privileges/nonexistent"))
        assertNull(objectProcessor.navigateObject(user, "addresses[100]/type"))
    }

    @Test
    fun `navigateObject should handle complex LinkedHashMap scenarios`() {
        // Given
        val response = createRestApiResponse()

        // When & Then - Complex REST API response navigation
        assertEquals("john@example.com", objectProcessor.navigateObject(response, "user/profile/contact/email"))
        assertEquals(true, objectProcessor.navigateObject(response, "settings[notifications]/email"))
        assertEquals("admin", objectProcessor.navigateObject(response, "roles/admin"))
        assertEquals("premium", objectProcessor.navigateObject(response, "tags/premium"))
    }

    @Test
    fun `navigateObject should handle edge cases with LinkedHashMap`() {
        // Given
        val response = createRestApiResponse()

        // When & Then - Edge cases that should return null
        assertNull(objectProcessor.navigateObject(response, "user/profile/nonexistent"))
        assertNull(objectProcessor.navigateObject(response, "settings[nonexistent]/property"))
        assertNull(objectProcessor.navigateObject(response, "nonexistent[0]"))
        assertNull(objectProcessor.navigateObject(response, "roles/nonexistent"))
        assertNull(objectProcessor.navigateObject(response, "metadata/createdBy"))
    }
}