package fr.julm.keycloak.providers.auth.cloudfront.test.integration;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.wait.strategy.Wait;

@Testcontainers
public class MultiVersionKeycloakTest {

    private static final int KEYCLOAK_PORT = 8080;

    @ParameterizedTest
    @ValueSource(strings = {
        // "22.0.0",  // Older LTS version
        // "23.0.0",
        // "24.0.0",
        // "25.0.0",
        "26.0.0"   // Latest version
    })
    void shouldWorkWithKeycloakVersion(String keycloakVersion) {
        try (@SuppressWarnings("resource")
        GenericContainer<?> keycloak = new GenericContainer<>(
                DockerImageName.parse("quay.io/keycloak/keycloak:" + keycloakVersion))
                .withExposedPorts(KEYCLOAK_PORT)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withCommand("start-dev")
                .waitingFor(Wait.forHttp("/").forPort(KEYCLOAK_PORT))) {

            keycloak.start();

            // Add your compatibility tests here
            // This could include:
            // - Deploying your extension
            // - Creating a test realm
            // - Testing authentication flow
        }
    }
}
