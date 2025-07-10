package group.phorus.auth.commons.bdd.app.repositories

import group.phorus.auth.commons.bdd.app.model.Document
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface DocumentRepository: JpaRepository<Document, UUID>