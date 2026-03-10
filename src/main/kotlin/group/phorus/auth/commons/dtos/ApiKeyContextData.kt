package group.phorus.auth.commons.dtos

/**
 * Data available after successful API key authentication.
 *
 * Populated by [group.phorus.auth.commons.filters.ApiKeyFilter] and accessible via
 * [group.phorus.auth.commons.context.ApiKeyContext].
 *
 * @property keyId The resolved identifier of the API key. When using static keys from
 *     configuration, this is the map key (e.g. `"partner-a"`). When using a custom
 *     [group.phorus.auth.commons.services.ApiKeyValidator], this is whatever the validator returns.
 * @property metadata Additional key-value metadata from the validator. Empty when using static keys.
 */
data class ApiKeyContextData(
    val keyId: String?,
    val metadata: Map<String, String> = emptyMap(),
)
