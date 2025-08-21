package fr.julm.keycloak.providers.auth.cloudfront.it;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

import io.restassured.response.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.info.ServerInfoRepresentation;

/**
 * Integration tests for CloudFront Auth extension.
 * Tests the extension functionality in a real Keycloak instance.
 */
public class KeycloakInstanceIT extends AbstractKeycloakIntegrationTest {
    // =====[ KEYCLOAK INSTANCE CHECKS ]===== //
    @Test
    @DisplayName("Keycloak Instance Infos Checks")
    void testKeycloakIsRunning() {
        ServerInfoRepresentation serverInfo = getAdminClient().serverInfo().getInfo();
        String serverVersion = serverInfo.getSystemInfo().getVersion();
        String expectedVersion = System.getProperty("keycloak-version.major-minor");

        LOGGER.info("=> Version of tested Keycloak instance: " + serverVersion);

        if (expectedVersion == null) {
            LOGGER.warning("!! The Java property 'keycloak-version.major-minor' not set, " +
                "consider Keycloak instance version is correct. !!");
        }
        else {
            assertTrue(serverVersion.startsWith(expectedVersion),
                "Expected Keycloak version to start with " + expectedVersion + ", but got: " + serverVersion);
        }
    }

    @Test
    @DisplayName("Test realm cloudfront-test exists")
    void testRealmExists() {
        // Test that the realm configured by the configurator exists
        Response response = given()
            .when()
            .get("/realms/cloudfront-test")
            .then()
            .statusCode(200)
            .extract()
            .response();
        
        String body = response.getBody().asString();
        assertTrue(body.contains(ITEnvConfig.REALM_NAME),
            "Realm response should contain realm name (" + ITEnvConfig.REALM_NAME + ")");
    }
}
