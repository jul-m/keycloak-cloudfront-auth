package fr.julm.keycloak.providers.auth.cloudfront.it;

import io.restassured.RestAssured;
import java.util.Map;
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

    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "admin";
    public static final String REALM_NAME = "cloudfront-test";
    public static final String CLIENT_ID = "cloudfront-test-client";
    public static final String CLIENT_SECRET = "TestSecret123";
    public static final String USER_USERNAME_OK = "user1";
    public static final String USER_USERNAME_INVALID = "user2";
    public static final String USER_PASSWORD = "password123";
    public static final String HOME_URL = "http://localhost:8081";
    public static final String LANG = "en";
    public static final String CF_SIGN_KEY_ID = "ABCDEFG";
    public static final Map<String, String> DEFAULT_CONFIG_MAP = Map.of(
        "Auth Cookies Attributes", "Path=/; Secure; HttpOnly",
        "Access Roles", "[cloudfront-access]",
        "Display Request ID in Error Pages", "true",
        "Redirect Delay", "5",
        "Redirect Fallback Delay", "10"
    );

    protected static final Logger LOGGER = Logger.getLogger(AbstractKeycloakIntegrationTest.class.getName());

    protected static String keycloakHost;
    protected static int keycloakPort;
    protected static String keycloakBaseUrl;
    protected static Keycloak adminClient;

    private static class KeycloakAdminClientHolder {
        private static final Keycloak INSTANCE = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .username(ADMIN_USERNAME)
                .password(ADMIN_PASSWORD)
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
