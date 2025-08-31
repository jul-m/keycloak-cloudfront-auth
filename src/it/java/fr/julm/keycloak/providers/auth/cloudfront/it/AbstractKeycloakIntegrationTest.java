package fr.julm.keycloak.providers.auth.cloudfront.it;

import io.restassured.RestAssured;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;


/**
 * Base class for integration tests.
 * Connects to a Keycloak instance running in Docker.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractKeycloakIntegrationTest {
    protected static final Logger LOGGER = Logger.getLogger(AbstractKeycloakIntegrationTest.class.getName());

    protected static String keycloakHost;
    protected static int keycloakPort;
    protected static String keycloakBaseUrl;
    protected static Keycloak adminClient;

    private static class KeycloakAdminClientHolder {
        private static final Keycloak INSTANCE = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .username(ITEnvConfig.ADMIN_USERNAME)
                .password(ITEnvConfig.ADMIN_PASSWORD)
                .clientId("admin-cli")
                .build();
    }

    protected static Keycloak getAdminClient() {
        return KeycloakAdminClientHolder.INSTANCE;
    }

    @BeforeAll
    void setupRestAssured() {
        // Get connection details from environment or use defaults
        keycloakHost = System.getenv().getOrDefault("KEYCLOAK_HOST", "localhost");
        keycloakPort = Integer.parseInt(System.getenv().getOrDefault("KEYCLOAK_PORT", "8080"));
        keycloakBaseUrl = "http://" + keycloakHost + ":" + keycloakPort;
        
        // Configure RestAssured to point to the running Keycloak
        RestAssured.baseURI = keycloakBaseUrl;
        RestAssured.port = keycloakPort;
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        
        LOGGER.info("=> Running tests against Keycloak at: " + keycloakBaseUrl);

        // Access the admin client to ensure initialization
        adminClient = getAdminClient();
    }
}
