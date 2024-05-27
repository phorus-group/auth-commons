package group.phorus.auth.commons.bdd

import group.phorus.auth.commons.bdd.app.TestApp
import io.cucumber.spring.CucumberContextConfiguration
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles


@SpringBootTest(classes = [TestApp::class])
@CucumberContextConfiguration
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class CucumberSpringConfiguration
