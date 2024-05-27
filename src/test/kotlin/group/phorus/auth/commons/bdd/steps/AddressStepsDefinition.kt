package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.bdd.app.dtos.AddressResponse
import group.phorus.auth.commons.bdd.app.model.Address
import group.phorus.auth.commons.bdd.app.repositories.AddressRepository
import group.phorus.auth.commons.bdd.app.repositories.UserRepository
import group.phorus.mapper.mapping.extensions.mapTo
import group.phorus.test.commons.bdd.BaseResponseScenarioScope
import group.phorus.test.commons.bdd.BaseScenarioScope
import io.cucumber.datatable.DataTable
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import org.junit.jupiter.api.Assertions.assertEquals
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.web.reactive.server.expectBody
import java.util.*


class AddressStepsDefinition(
    @Autowired private val baseScenarioScope: BaseScenarioScope,
    @Autowired private val responseScenarioScope: BaseResponseScenarioScope,
    @Autowired private val addressRepository: AddressRepository,
    @Autowired private val userRepository: UserRepository,
) {
    @Given("the given Address exists:")
    fun `the given Address exists`(data: DataTable) {
        val userId = (baseScenarioScope.objects["userId"] as String).let { id -> UUID.fromString(id) }
        val user = userRepository.findById(userId).get()

        val address = data.asMaps().first().let {
            Address(
                address = it["address"],
                user = user,
            )
        }

        baseScenarioScope.objects["addressResponse"] = addressRepository.saveAndFlush(address).mapTo<AddressResponse>()!!
        baseScenarioScope.objects["addressId"] = (baseScenarioScope.objects["addressResponse"] as AddressResponse).id!!.toString()
    }


    @Then("the service returns the Address")
    fun `the service returns the address`() {
        val addressResponse = responseScenarioScope.responseSpec!!
            .expectBody<AddressResponse>().returnResult().responseBody!!

        assertEquals(baseScenarioScope.objects["addressResponse"] as AddressResponse, addressResponse)
    }
}