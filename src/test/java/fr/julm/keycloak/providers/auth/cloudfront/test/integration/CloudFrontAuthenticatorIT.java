package fr.julm.keycloak.providers.auth.cloudfront.test.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.wait.strategy.Wait;

@Testcontainers
public class CloudFrontAuthenticatorIT {

    private static final int KEYCLOAK_PORT = 8080;

    @SuppressWarnings("resource")
    @Container
    private final GenericContainer<?> keycloak = new GenericContainer<>(
            DockerImageName.parse("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version", "26.0.0")))
            .withExposedPorts(KEYCLOAK_PORT)
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .waitingFor(Wait.forHttp("/").forPort(KEYCLOAK_PORT));

    @BeforeEach
    void setUp() {
        // Setup test realm and required configuration
    }

    @Test
    void shouldAuthenticateWithValidCloudFrontRequest() {
        // Add integration test here
    }

    // Add more integration tests
}
