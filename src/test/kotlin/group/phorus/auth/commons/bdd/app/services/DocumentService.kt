package group.phorus.auth.commons.bdd.app.services

import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.model.Document
import java.util.*

interface DocumentService {
    suspend fun create(documentDTO: DocumentDTO): UUID
    suspend fun findById(id: UUID): Document
    suspend fun update(id: UUID, documentDTO: DocumentDTO): Document
    suspend fun delete(id: UUID)
}