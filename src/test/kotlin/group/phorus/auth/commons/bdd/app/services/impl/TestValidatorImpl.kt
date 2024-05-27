package group.phorus.auth.commons.bdd.app.services.impl

import group.phorus.auth.commons.services.Validator
import io.jsonwebtoken.Claims
import org.springframework.stereotype.Service

@Service
class TestValidatorImpl : Validator {
    override fun accepts(property: String): Boolean = property == "tokenThingy"

    override fun isValid(value: String, properties: Map<String, String>): Boolean =
        properties[Claims.SUBJECT] != null && value.lowercase() == "true"
}