import com.kageiit.jacobo.JacoboTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.springframework.boot.gradle.tasks.bundling.BootJar
import java.net.URI
import java.time.LocalDate

plugins {
    id("org.springframework.boot").version("4.0.3")
    id("io.spring.dependency-management").version("1.1.7")
    kotlin("jvm").version("2.3.10")
    kotlin("plugin.spring").version("2.3.10")
    id("org.jetbrains.dokka").version("2.1.0")
    id("com.vanniktech.maven.publish") version "0.34.0"
    id("com.kageiit.jacobo") version "2.1.0"
    jacoco
}

ext["jackson-2-bom.version"] = "2.21.1"
ext["jackson-bom.version"] = "3.1.0"

group = "group.phorus"
description = "DEPRECATED: Use authn-core:1.0.0 + authn-spring-boot-starter:2.0.0 instead. Library containing common AuthN logic for Spring based services."
version = "2.0.12"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-webclient")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-configuration-processor")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    api("org.springframework.security:spring-security-crypto")

    // Kotlin
    implementation(kotlin("reflect"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")

    // Phorus
    implementation("group.phorus:mapper:1.2.0")
    implementation("group.phorus:exception-handling:1.1.3")
    implementation("group.phorus:metrics-commons:2.0.2")

    // JWT
    api("org.bouncycastle:bcprov-jdk18on:1.80")
    api("io.jsonwebtoken:jjwt-api:0.13.0")
    api("io.jsonwebtoken:jjwt-impl:0.13.0")
    api("io.jsonwebtoken:jjwt-jackson:0.13.0")

    // Test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-webtestclient")
    testImplementation("group.phorus:test-commons:1.1.6")
    testImplementation("org.mockito.kotlin:mockito-kotlin:6.2.3")
    testImplementation("org.wiremock:wiremock-jetty12:3.13.1")
    testImplementation("io.mockk:mockk:1.14.9")
    testRuntimeOnly("com.h2database:h2")
}

// Force Jetty 12.0.16 for WireMock compatibility (SB 4.0 upgrades to 12.1.x which breaks WireMock)
configurations.matching { it.name.startsWith("test") }.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group.startsWith("org.eclipse.jetty")) {
            useVersion("12.0.16")
        }
    }
}

val repoUrl = System.getenv("GITHUB_REPOSITORY")?.let { "https://github.com/$it" }
    ?: "https://github.com/phorus-group/auth-commons"

tasks {
    getByName<BootJar>("bootJar") {
        enabled = false
    }

    // Jacoco config
    jacocoTestReport {
        executionData.setFrom(fileTree(project.layout.buildDirectory).include("/jacoco/*.exec"))

        reports {
            xml.required.set(true)
            csv.required.set(true)
        }

        finalizedBy("jacobo")
    }

    withType<Test> {
        useJUnitPlatform()

        finalizedBy(jacocoTestReport)

        // If parallel tests start failing, instead of disabling this, take a look at @Execution(ExecutionMode.SAME_THREAD)
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
        systemProperty("junit.jupiter.execution.parallel.mode.default", "same_thread")
        systemProperty("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")

        finalizedBy(jacocoTestReport)
    }

    register<JacoboTask>("jacobo") {
        description = "Transforms jacoco xml report to cobertura"
        group = "verification"

        jacocoReport = file("${layout.buildDirectory.asFile.get()}/reports/jacoco/test/jacocoTestReport.xml")
        coberturaReport = file("${layout.buildDirectory.asFile.get()}/reports/cobertura/cobertura.xml")
        includeFileNames = emptySet()

        val field = JacoboTask::class.java.getDeclaredField("srcDirs")
        field.isAccessible = true
        field.set(this, sourceSets["main"].allSource.srcDirs.map { it.path }.toTypedArray())

        dependsOn(jacocoTestReport)
    }

    withType<KotlinCompile> {
        compilerOptions {
            freeCompilerArgs = listOf("-Xjsr305=strict")
            jvmTarget.set(JvmTarget.fromTarget(java.targetCompatibility.toString()))
        }
    }

    dokka {
        val branch = System.getenv("GITHUB_REF_NAME") ?: "main"
        val currentYear = LocalDate.now().year

        dokkaPublications.html {
            outputDirectory.set(layout.buildDirectory.dir("dokka/html"))
        }

        dokkaSourceSets.configureEach {
            reportUndocumented.set(true)
            jdkVersion.set(java.targetCompatibility.majorVersion.toInt())
            sourceRoots.from(file("src"))

            sourceLink {
                localDirectory.set(file("src/main/kotlin"))
                remoteUrl.set(URI("$repoUrl/tree/$branch/src/main/kotlin"))
                remoteLineSuffix.set("#L")
            }
        }

        pluginsConfiguration.html {
            footerMessage.set("© $currentYear Phorus Group - Licensed under the <a target=\"_blank\" href=\"$repoUrl/blob/$branch/LICENSE\">Apache 2 license</a>.")
        }
    }

}

afterEvaluate {
    tasks.named("generateMetadataFileForMavenPublication") {
        dependsOn("dokkaJavadocJar")
    }
}

mavenPublishing {
    coordinates(
        groupId = project.group.toString(),
        artifactId = project.name,
        version = project.version.toString()
    )

    pom {
        name.set(project.name)
        description.set(project.description ?: "")
        url.set(repoUrl)

        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }

        developers {
            developer {
                id.set("irios.phorus")
                name.set("Martin Rios")
                email.set("irios@phorus.group")
                organization.set("Phorus Group")
                organizationUrl.set("https://phorus.group")
            }
        }

        scm {
            url.set(repoUrl)
            connection.set("scm:git:$repoUrl.git")
            developerConnection.set("scm:git:$repoUrl.git")
        }
    }

    publishToMavenCentral(automaticRelease = true)
    signAllPublications()
}
