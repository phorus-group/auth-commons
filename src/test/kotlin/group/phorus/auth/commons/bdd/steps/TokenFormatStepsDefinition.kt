package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.config.SecurityConfiguration
import group.phorus.auth.commons.config.TokenFormat
import io.cucumber.java.After
import io.cucumber.java.Before
import org.springframework.beans.factory.annotation.Autowired
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.*

class TokenFormatStepsDefinition(
    @Autowired private val securityConfiguration: SecurityConfiguration,
) {

    companion object {
        private val signingKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        val signingPrivateKeyBase64: String =
            Base64.getEncoder().encodeToString(signingKeyPair.private.encoded)
        val signingPublicKeyBase64: String =
            Base64.getEncoder().encodeToString(signingKeyPair.public.encoded)
    }

    private var originalFormat: TokenFormat? = null
    private var originalSigningPrivateKey: String? = null
    private var originalSigningPublicKey: String? = null
    private var originalSigningAlgorithm: String? = null

    private fun saveOriginalConfig() {
        originalFormat = securityConfiguration.jwt.tokenFormat
        originalSigningPrivateKey = securityConfiguration.jwt.signing.encodedPrivateKey
        originalSigningPublicKey = securityConfiguration.jwt.signing.encodedPublicKey
        originalSigningAlgorithm = securityConfiguration.jwt.signing.algorithm
    }

    private fun applySigningKeys() {
        securityConfiguration.jwt.signing.algorithm = "EC"
        securityConfiguration.jwt.signing.encodedPrivateKey = signingPrivateKeyBase64
        securityConfiguration.jwt.signing.encodedPublicKey = signingPublicKeyBase64
    }

    @Before("@jws")
    fun switchToJws() {
        saveOriginalConfig()
        securityConfiguration.jwt.tokenFormat = TokenFormat.JWS
        applySigningKeys()
    }

    @Before("@nested-jwe")
    fun switchToNestedJwe() {
        saveOriginalConfig()
        securityConfiguration.jwt.tokenFormat = TokenFormat.NESTED_JWE
        applySigningKeys()
    }

    @After("@jws or @nested-jwe")
    fun resetFormat() {
        originalFormat?.let { securityConfiguration.jwt.tokenFormat = it }
        originalSigningPrivateKey.let { securityConfiguration.jwt.signing.encodedPrivateKey = it }
        originalSigningPublicKey.let { securityConfiguration.jwt.signing.encodedPublicKey = it }
        originalSigningAlgorithm?.let { securityConfiguration.jwt.signing.algorithm = it }

        originalFormat = null
        originalSigningPrivateKey = null
        originalSigningPublicKey = null
        originalSigningAlgorithm = null
    }
}
