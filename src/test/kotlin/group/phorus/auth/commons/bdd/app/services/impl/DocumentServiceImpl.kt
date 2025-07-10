package group.phorus.auth.commons.bdd.app.services.impl

import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.model.Document
import group.phorus.auth.commons.bdd.app.repositories.DocumentRepository
import group.phorus.auth.commons.bdd.app.services.DocumentService
import group.phorus.auth.commons.context.AuthContext
import group.phorus.exception.handling.NotFound
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Service
import java.util.*

@Service
class DocumentServiceImpl(
    private val documentRepository: DocumentRepository,
) : DocumentService {

    override suspend fun create(documentDTO: DocumentDTO): UUID {
        val authContext = AuthContext.context.get()
        val document = Document(
            title = documentDTO.title,
            content = documentDTO.content,
            ownerId = authContext.userId,
            sensitiveInfo = documentDTO.sensitiveInfo,
            restrictedData = documentDTO.restrictedData,
        )
        return withContext(Dispatchers.IO) {
            documentRepository.save(document).id!!
        }
    }

    override suspend fun findById(id: UUID): Document = withContext(Dispatchers.IO) {
        documentRepository.findById(id).orElseThrow {
            NotFound("Document not found with id: $id")
        }
    }

    override suspend fun update(id: UUID, documentDTO: DocumentDTO): Document {
        val document = findById(id)
        documentDTO.title?.let { document.title = it }
        documentDTO.content?.let { document.content = it }
        documentDTO.sensitiveInfo?.let { document.sensitiveInfo = it }
        documentDTO.restrictedData?.let { document.restrictedData = it }

        return withContext(Dispatchers.IO) {
            documentRepository.save(document)
        }
    }

    override suspend fun delete(id: UUID) = withContext(Dispatchers.IO) {
        documentRepository.deleteById(id)
    }
}