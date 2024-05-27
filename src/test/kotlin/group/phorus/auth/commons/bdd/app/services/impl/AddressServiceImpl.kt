package group.phorus.auth.commons.bdd.app.services.impl

import group.phorus.auth.commons.bdd.app.model.Address
import group.phorus.auth.commons.bdd.app.repositories.AddressRepository
import group.phorus.auth.commons.bdd.app.services.AddressService
import group.phorus.exception.handling.Unauthorized
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Service
import java.util.*

@Service
class AddressServiceImpl(
    private val addressRepository: AddressRepository,
) : AddressService {
    override suspend fun findById(id: UUID): Address = withContext(Dispatchers.IO) {
        addressRepository.findById(id).orElseThrow {
            Unauthorized("Address not found with id: $id")
        }
    }
}
