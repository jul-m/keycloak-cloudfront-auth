package fr.julm.keycloak.providers.auth.cloudfront.it;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthProviderConfig;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.*;
import org.keycloak.representations.idm.*;
import org.keycloak.representations.info.*;

// JSON parsing is done via simple regex here to avoid adding a dependency on Gson

/**
 * Integration tests for CloudFront Auth extension.
 * Tests the extension functionality in a real Keycloak instance.
 */
public class CloudFrontAuthExtensionIT extends AbstractKeycloakIntegrationTest {

    // =====[ CONSTANTS ]===== //
    protected static String EXTENSION_ENDPOINT = "/cloudfront-auth";
    protected static String CALLBACK_URI = EXTENSION_ENDPOINT + CloudFrontAuthProviderConfig.REDIRECT_URI_PATH;
    protected static String CF_REDIRECT_403_URI = EXTENSION_ENDPOINT + "/.cdn-auth/_cf_redirect_403";


    // =====[ BASE EXTENSION CHECKS ]===== //
    @Test
    @DisplayName("Test CloudFront Auth extension base endpoint are available")
    void testCloudFrontAuthExtensionLoaded() {
        String testUrl = "/cloudfront-auth/.cdn-auth/";
        
        // Test the CloudFront Auth endpoint - should respond (even if with error for missing headers)
        given()
            .when().get(testUrl)
            .then().statusCode(405)
            .extract().response();
    }

    @Test
    @DisplayName("Verify CloudFront Auth extension is loaded and configuration is correct")
    void testCloudFrontAuthExtensionLoadedAndConfig() {
        ServerInfoRepresentation serverInfo = getAdminClient().serverInfo().getInfo();

        // Vérifier la présence de cloudfront-auth
        ProviderRepresentation cloudfrontAuthExtension = serverInfo.getProviders()
                                                            .get("realm-restapi-extension")
                                                            .getProviders()
                                                            .get("cloudfront-auth");
        assertNotNull(cloudfrontAuthExtension,
            "CloudFront Auth extension should be present in realm-restapi-extension");

        // Vérifier les informations opérationnelles
        Map<String, String> operationalInfo = cloudfrontAuthExtension.getOperationalInfo();
        assertNotNull(operationalInfo, "Operational info for CloudFront Auth extension should be present");

        String buildName = System.getProperty("build-name");
        if (buildName == null) {
            LOGGER.warning("=> build-name property not set, Version filed in operational info not checked.");
        } else {
            assertEquals(buildName, operationalInfo.get("Version"),
                "Version in operational info should match with build-name property.");
        }

        ITEnvConfig.PROVIDER_CFG.forEach((key, expectedValue) -> {
            assertEquals(expectedValue, operationalInfo.get(key), key + " should match");
        }); 

        // Vérifier la présence de oidc-cloudfront-auth-config-mapper dans protocol-mapper
        ProviderRepresentation authConfigMapper = serverInfo.getProviders()
                                                    .get("protocol-mapper")
                                                    .getProviders()
                                                    .get("oidc-cloudfront-auth-config-mapper");
        assertNotNull(authConfigMapper,
            "oidc-cloudfront-auth-config-mapper should be present in protocol-mapper");

        // Vérifier la configuration dans protocolMapperTypes pour openid-connect
        ProtocolMapperTypeRepresentation oidcAuthConfigMapper = serverInfo.getProtocolMapperTypes()
                                    .get("openid-connect")
                                    .stream()
                                    .filter(mapper -> "oidc-cloudfront-auth-config-mapper".equals(mapper.getId()))
                                    .findFirst()
                                    .orElse(null);
        assertNotNull(oidcAuthConfigMapper,
            "oidc-cloudfront-auth-config-mapper should be present in openid-connect mappers");

        List<String> actualProperties = oidcAuthConfigMapper.getProperties().stream()
                                        .map(property -> property.getName())
                                        .collect(Collectors.toList());
        assertTrue(actualProperties.containsAll(
            List.of("jwt-cookie.enabled", "jwt-cookie.name", "jwt-cookie.attributes")),
            "All expected properties should be present"
        );

        // Vérifier les propriétés dans componentTypes pour allowed-protocol-mappers
        List<ComponentTypeRepresentation> clientRegistrationPolicies = serverInfo.getComponentTypes()
                        .get("org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy");
        assertTrue(clientRegistrationPolicies.stream().anyMatch(
            component -> "allowed-protocol-mappers".equals(component.getId())),
            "allowed-protocol-mappers should be present in ClientRegistrationPolicy component types");
    }

    @Test
    @DisplayName("CORS OPTIONS returns appropriate headers")
    void testCorsOptions() {
        String testUrl = "/cloudfront-auth/.cdn-auth/some/path";

        Response response = given()
                .when().options(testUrl)
                .then().statusCode(200)
                .extract().response();

        assertEquals("*", response.getHeader("Access-Control-Allow-Origin"),
            "CORS header 'Access-Control-Allow-Origin' should be present and equal to '*'");
        assertTrue(response.getHeader("Access-Control-Allow-Methods").contains("GET"),
            "CORS header 'Access-Control-Allow-Methods' should be present and contain 'GET'");
        assertTrue(response.getHeader("Access-Control-Allow-Headers").contains("Content-Type"),
            "CORS header 'Access-Control-Allow-Headers' should be present and contain 'Content-Type'");
    }


    // =====[ .cdn-auth/_cf_redirect_403 TESTS ]===== //
    @Test
    @DisplayName("Redirect endpoint returns 200 with correct HTML for valid client credentials")
    void testRedirectValidClientCredentialsHtml() throws IOException {
    Response response = given()
        .header("kc-realm-name", ITEnvConfig.REALM_NAME)
        .header("kc-client-id", ITEnvConfig.CLIENT_ID)
        .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
        .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
                .when().get(CF_REDIRECT_403_URI)
                .then().statusCode(200)
                .extract().response();

        String responseBody = response.getBody().asString();

        // Load the original HTML template
        String templatePath = "src/main/resources/html/redirect.ftl";
        String templateContent = new String(Files.readAllBytes(Paths.get(templatePath)), StandardCharsets.UTF_8);

        // Load msg from properties file
        Properties msg = new Properties();
        try (InputStream input = Files.newInputStream(
            Paths.get("src/main/resources/messages/messages_"+ ITEnvConfig.LANG +".properties"))) {
                msg.load(input);
        }

        // Construct the auth URL in a readable format
        String redirectUri = URLEncoder.encode(ITEnvConfig.HOME_URL + "/.cdn-auth/callback", StandardCharsets.UTF_8);
        String authUrl = keycloakBaseUrl + "/realms/" + ITEnvConfig.REALM_NAME + "/protocol/openid-connect/auth" +
            "?client_id=" + ITEnvConfig.CLIENT_ID +
                    "&response_type=code" +
                    "&redirect_uri=" + redirectUri +
                    "&scope=openid";

        // Replace variables in the template using msg
        String expectedHtml = templateContent
            .replace("${msg(\"redirectToAuthService\")}", msg.getProperty("redirectToAuthService"))
            .replace("${redirectFallbackDelay}", ITEnvConfig.PROVIDER_CFG.get("Redirect Fallback Delay"))
            .replace("${authUrl}", authUrl)
            .replace("${msg(\"clickHereIfNoRedirect\")}", msg.getProperty("clickHereIfNoRedirect"))
            .replace("${redirectUriPath}", CloudFrontAuthProviderConfig.REDIRECT_URI_PATH)
            .replace("${redirectDelay}", ITEnvConfig.PROVIDER_CFG.get("Redirect Delay"))
            .replace("${msg(\"javascriptDisabledWarning\")}", msg.getProperty("javascriptDisabledWarning"));

        assertEquals(expectedHtml.trim(), responseBody.trim(), "HTML response should match expected content");
    }

    @Test
    @DisplayName("Redirect endpoint returns 400 when required headers are missing")
    void testRedirectMissingHeaders() {
        given()
            .when().get(CF_REDIRECT_403_URI)
            .then().statusCode(400)
            .extract().response();
    }

    @Test
    @DisplayName("Redirect endpoint returns 401 for invalid client credentials")
    void testRedirectInvalidClientCredentials() {
        given()
            .header("kc-realm-name", ITEnvConfig.REALM_NAME)
            .header("kc-client-id", ITEnvConfig.CLIENT_ID)
            .header("kc-client-secret", "WrongSecret")
            .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
            .when().get(CF_REDIRECT_403_URI)
            .then().statusCode(401)
            .extract().response();
    }


    // =====[ .cdn-auth/callback TESTS ]===== //
    @Test
    @DisplayName("Callback endpoint returns 400 when 'code' query param is missing")
    void testCallbackMissingCode() {
        given()
            .header("kc-realm-name", ITEnvConfig.REALM_NAME)
            .header("kc-client-id", ITEnvConfig.CLIENT_ID)
            .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
            .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
            .when().get(CALLBACK_URI)
            .then().statusCode(400)
            .extract().response();
    }

    @Test
    @DisplayName("Callback endpoint returns 401 when 'code' query param is invalid")
    void testCallbackInvalidCode() {
        given()
            .header("kc-realm-name", ITEnvConfig.REALM_NAME)
            .header("kc-client-id", ITEnvConfig.CLIENT_ID)
            .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
            .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
            .queryParam("original_uri", ITEnvConfig.HOME_URL + "/")
            .queryParam("session_state", UUID.randomUUID().toString())
            .queryParam("iss", keycloakBaseUrl + "/realms/" + ITEnvConfig.REALM_NAME)
            .queryParam("code", "invalid_code")
            .redirects().follow(false)
            .when().get(CALLBACK_URI)
            .then().statusCode(401)
            .extract().response();
    }

    @Test
    @DisplayName("Simulate successful authentication using Keycloak tools")
    void testSuccessfulAuthenticationWithKeycloakTools() throws IOException, java.security.cert.CertificateException {
        String authorizationCode = KeycloakTestsTools.obtainAuthorizationCode(
            keycloakBaseUrl, ITEnvConfig.REALM_NAME, ITEnvConfig.HOME_URL, ITEnvConfig.CLIENT_ID,
            ITEnvConfig.USER_USERNAME_OK, ITEnvConfig.USER_PASSWORD
        );
        assertNotNull(authorizationCode, "Authorization code should not be null");

        // Call the callback endpoint with the obtained code and validate CloudFront cookies are set
        Response callbackResponse = given()
                    .header("kc-realm-name", ITEnvConfig.REALM_NAME)
                    .header("kc-client-id", ITEnvConfig.CLIENT_ID)
                    .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
                    .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
                    .queryParam("original_uri", ITEnvConfig.HOME_URL + "/")
                    .queryParam("session_state", UUID.randomUUID().toString())
                    .queryParam("iss", keycloakBaseUrl + "/realms/" + ITEnvConfig.REALM_NAME)
                    .queryParam("code", authorizationCode)
                    .redirects().follow(false)
                    .when().get(CALLBACK_URI)
                    .then().statusCode(302)
                    .extract().response();

        List<String> setCookies = callbackResponse.getHeaders().getValues("Set-Cookie");
        assertNotNull(setCookies);

        String combinedCookies = String.join("; ", setCookies);
        assertTrue(combinedCookies.contains("CloudFront-Policy"));
        assertTrue(combinedCookies.contains("CloudFront-Signature"));
        assertTrue(combinedCookies.contains("CloudFront-Key-Pair-Id"));

        getAdminClient().realm(ITEnvConfig.REALM_NAME).keys().getKeyMetadata().getKeys();
        String policyCookie = null;
        String signatureCookie = null;
        String keyPairIdCookie = null;
        Pattern cookiePattern = Pattern.compile(
            "(CloudFront-Policy|CloudFront-Signature|CloudFront-Key-Pair-Id)=([^;]+)");
        
        for (String sc : setCookies) {
            Matcher m = cookiePattern.matcher(sc);
            while (m.find()) {
                String name = m.group(1);
                String value = m.group(2);
                switch (name) {
                    case "CloudFront-Policy": policyCookie = value; break;
                    case "CloudFront-Signature": signatureCookie = value; break;
                    case "CloudFront-Key-Pair-Id": keyPairIdCookie = value; break;
                }
            }
        }

        assertNotNull(policyCookie, "Policy cookie should be present");
        assertNotNull(signatureCookie, "Signature cookie should be present");
        assertNotNull(keyPairIdCookie, "Key-Pair-Id cookie should be present");

        // Retrieve key metadata via admin client and extract certificate using utility
        KeysMetadataRepresentation keyMetadata = getAdminClient().realm(ITEnvConfig.REALM_NAME).keys().getKeyMetadata();
        PublicKey publicKey = null;
        try {
            publicKey = KeycloakTestsTools.getActiveRSAPublicKey(keyMetadata);
        } catch (Exception e) {
            fail("Failed to extract public key from key metadata: " + e.getMessage());
        }

        assertNotNull(publicKey, "Public key should be extracted from realm key metadata certificate");

        // Validate cookies and signature
        CloudFrontAuthTools.Result result = CloudFrontAuthTools.checkCloudFrontSignedCookies(
            publicKey, policyCookie, keyPairIdCookie, signatureCookie);
        assertTrue(result.signatureValid, "Signature should be valid");
        assertFalse(result.expired, "Policy should not be expired");
        assertNotNull(result.keyPairIdMatch);
        assertTrue(result.keyPairIdMatch.booleanValue(), "Key-Pair-Id should match expected configured value");
    }

    @Test
    @DisplayName("Loop detection: callback increments loop cookie and triggers error at threshold")
    void testLoopDetectionOnCallback() throws Exception {
        String cookieHeader = null;
        Pattern loopPattern = Pattern.compile("cloudfront_auth_loop=([0-9]+)");

        // Perform 10 consecutive successful callback flows, passing the loop cookie between calls
        for (int i = 1; i <= 10; i++) {
            String authorizationCode = KeycloakTestsTools.obtainAuthorizationCode(
                keycloakBaseUrl, ITEnvConfig.REALM_NAME, ITEnvConfig.HOME_URL, ITEnvConfig.CLIENT_ID,
                ITEnvConfig.USER_USERNAME_OK, ITEnvConfig.USER_PASSWORD);
            assertNotNull(authorizationCode, "Authorization code should not be null (iteration=" + i + ")");

            RequestSpecification req = given()
                .header("kc-realm-name", ITEnvConfig.REALM_NAME)
                .header("kc-client-id", ITEnvConfig.CLIENT_ID)
                .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
                .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
                .queryParam("original_uri", ITEnvConfig.HOME_URL + "/")
                .queryParam("session_state", UUID.randomUUID().toString())
                .queryParam("iss", keycloakBaseUrl + "/realms/" + ITEnvConfig.REALM_NAME)
                .queryParam("code", authorizationCode)
                .redirects().follow(false);

            if (cookieHeader != null) {
                req.header("Cookie", cookieHeader);
            }

            Response callbackResponse = req.when().get(CALLBACK_URI).andReturn();
            if (i < 10) {
                assertEquals(
                    302, callbackResponse.getStatusCode(), "Expected 302 before threshold (i=" + i + ")");
            } else {
                assertEquals(
                    310, callbackResponse.getStatusCode(), "Expected 310 at threshold (i=" + i + ")");
            }

            // Extract updated loop cookie from Set-Cookie headers
            List<String> setCookies = callbackResponse.getHeaders().getValues("Set-Cookie");
            assertNotNull(setCookies, "Set-Cookie headers should be present (i=" + i + ")");

            String loopSet = null;
            for (String sc : setCookies) {
                Matcher m = loopPattern.matcher(sc);
                if (m.find()) {
                    loopSet = m.group(0);
                    break;
                }
            }
            assertNotNull(loopSet, "Loop Set-Cookie should be present after callback (i=" + i + ")");

            // prepare Cookie header for next iteration
            Matcher mv = loopPattern.matcher(loopSet);
            if (mv.find()) {
                cookieHeader = "cloudfront_auth_loop=" + mv.group(1);
            } else {
                cookieHeader = null;
            }
        }
    }

    @Test
    @DisplayName("Try get signed cookies with user without required role")
    void testGetSignedCookiesWithUserWithoutRequiredRole() throws IOException {
        // Get authorization code for user without required role
        String authorizationCode = KeycloakTestsTools.obtainAuthorizationCode(
            keycloakBaseUrl, ITEnvConfig.REALM_NAME, ITEnvConfig.HOME_URL, ITEnvConfig.CLIENT_ID,
            ITEnvConfig.USER_USERNAME_INVALID, ITEnvConfig.USER_PASSWORD);
        assertNotNull(authorizationCode, "Authorization code should not be null");

        given()
            .header("kc-realm-name", ITEnvConfig.REALM_NAME)
            .header("kc-client-id", ITEnvConfig.CLIENT_ID)
            .header("kc-client-secret", ITEnvConfig.CLIENT_SECRET)
            .header("kc-cf-sign-key-id", ITEnvConfig.CF_SIGN_KEY_ID)
            .queryParam("original_uri", ITEnvConfig.HOME_URL + "/")
            .queryParam("session_state", UUID.randomUUID().toString())
            .queryParam("iss", keycloakBaseUrl + "/realms/" + ITEnvConfig.REALM_NAME)
            .queryParam("code", authorizationCode)
            .redirects().follow(false)
            .when().get(CALLBACK_URI)
            .then().statusCode(401)
            .extract().response();
    }
}
