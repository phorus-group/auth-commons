package group.phorus.auth.commons.bdd.app.dtos

import group.phorus.mapper.mapping.MapFrom
import java.util.*

data class AddressResponse(
    var id: UUID? = null,
    var address: String? = null,

    @MapFrom(["user/id"])
    var userId: UUID? = null,
)
