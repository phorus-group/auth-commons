package group.phorus.auth.commons.bdd.app.controllers

import group.phorus.auth.commons.bdd.app.dtos.AddressResponse
import group.phorus.auth.commons.bdd.app.services.AddressService
import group.phorus.mapper.mapping.extensions.mapTo
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@RequestMapping("/address")
class AddressController(
    private val addressService: AddressService,
) {
    @GetMapping("/{addressId}")
    suspend fun findByID(@PathVariable addressId: UUID): AddressResponse =
        addressService.findById(addressId).mapTo<AddressResponse>()!!
}