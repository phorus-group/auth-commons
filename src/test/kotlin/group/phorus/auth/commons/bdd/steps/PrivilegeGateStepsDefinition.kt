package group.phorus.auth.commons.bdd.steps

import group.phorus.auth.commons.config.PrivilegeGate
import group.phorus.auth.commons.config.SecurityConfiguration
import io.cucumber.java.After
import io.cucumber.java.Before
import org.springframework.beans.factory.annotation.Autowired

class PrivilegeGateStepsDefinition(
    @Autowired private val securityConfiguration: SecurityConfiguration,
) {
    private var originalPrivilegeGates: List<PrivilegeGate>? = null

    @Before("@privilege-gates")
    fun setupPrivilegeGates() {
        originalPrivilegeGates = securityConfiguration.filters.token.privilegeGates.toList()

        securityConfiguration.filters.token.privilegeGates = listOf(
            // /privilege-gated/admin: requires "admin" OR "manager"
            PrivilegeGate(path = "/privilege-gated/admin", privileges = listOf("admin", "manager")),

            // /privilege-gated/reports (GET only): requires "reports:read"
            PrivilegeGate(path = "/privilege-gated/reports", method = "GET", privileges = listOf("reports:read")),

            // /privilege-gated/dual: two gates (AND) - requires "admin" AND "finance"
            PrivilegeGate(path = "/privilege-gated/dual", privileges = listOf("admin")),
            PrivilegeGate(path = "/privilege-gated/dual", privileges = listOf("finance")),
        )
    }

    @After("@privilege-gates")
    fun restorePrivilegeGates() {
        originalPrivilegeGates?.let {
            securityConfiguration.filters.token.privilegeGates = it
        }
    }
}
