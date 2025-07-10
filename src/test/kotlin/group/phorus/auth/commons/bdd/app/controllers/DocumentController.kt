package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.bdd.app.dtos.DocumentDTO
import group.phorus.auth.commons.bdd.app.dtos.DocumentResponse
import group.phorus.auth.commons.bdd.app.services.DocumentService
import group.phorus.mapper.mapping.extensions.mapTo
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.net.URI
import java.util.*

@RestController
@RequestMapping("/document")
class DocumentController(
    private val documentService: DocumentService,
) {

    @PostMapping
    suspend fun create(@RequestBody documentDTO: DocumentDTO): ResponseEntity<Void> {
        val id = documentService.create(documentDTO)
        return ResponseEntity.created(URI.create("/document/$id")).build()
    }

    @GetMapping("/{documentId}")
    suspend fun findById(@PathVariable documentId: UUID): DocumentResponse =
        documentService.findById(documentId).mapTo<DocumentResponse>()!!

    @PutMapping("/{documentId}")
    suspend fun update(
        @PathVariable documentId: UUID,
        @RequestBody documentDTO: DocumentDTO
    ): DocumentResponse = documentService.update(documentId, documentDTO).mapTo<DocumentResponse>()!!

    @DeleteMapping("/{documentId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun delete(@PathVariable documentId: UUID) = documentService.delete(documentId)
}