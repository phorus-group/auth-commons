package group.phorus.auth.commons.bdd.app.repositories

import group.phorus.auth.commons.bdd.app.model.Device
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface DeviceRepository: JpaRepository<Device, UUID> {
    fun findByNameAndUserId(name: String, userId: UUID): Optional<Device>

    @Query("select d from Device d where d.user.id = ?1 and (d.refreshTokenJTI = ?2 or d.accessTokenJTI = ?2)")
    fun findByUserIdAndJTI(userId: UUID, jti: String): Optional<Device>
}
