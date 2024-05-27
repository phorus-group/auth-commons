package group.phorus.auth.commons.services

import group.phorus.auth.commons.dtos.AccessToken
import java.util.*

interface TokenFactory {
    suspend fun createAccessToken(userId: UUID, privileges: List<String>, properties: Map<String, String> = emptyMap()): AccessToken
    suspend fun createRefreshToken(userId: UUID, expires: Boolean, properties: Map<String, String> = emptyMap()): String
}