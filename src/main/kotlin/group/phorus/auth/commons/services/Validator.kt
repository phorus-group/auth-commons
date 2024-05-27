package group.phorus.auth.commons.services

interface Validator {
    fun accepts(property: String): Boolean
    fun isValid(value: String, properties: Map<String, String> = emptyMap()): Boolean
}