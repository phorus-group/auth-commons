package group.phorus.auth.commons.bdd.app.services

import group.phorus.auth.commons.bdd.app.model.Address
import java.util.*

interface AddressService {
    suspend fun findById(id: UUID): Address
}
