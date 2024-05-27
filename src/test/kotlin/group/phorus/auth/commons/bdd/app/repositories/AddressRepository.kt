package group.phorus.auth.commons.bdd.app.repositories

import group.phorus.auth.commons.bdd.app.model.Address
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface AddressRepository: JpaRepository<Address, UUID>
