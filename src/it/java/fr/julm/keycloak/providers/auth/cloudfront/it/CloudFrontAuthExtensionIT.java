package fr.julm.keycloak.providers.auth.cloudfront.it;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

import io.restassured.response.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ComponentTypeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperTypeRepresentation;
import org.keycloak.representations.info.ProviderRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthProviderConfig;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.keycloak.representations.idm.KeysMetadataRepresentation;

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

        DEFAULT_CONFIG_MAP.forEach((key, expectedValue) -> {
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
                .header("kc-realm-name", REALM_NAME)
                .header("kc-client-id", CLIENT_ID)
                .header("kc-client-secret", CLIENT_SECRET)
                .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
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
            Paths.get("src/main/resources/messages/messages_"+ LANG +".properties"))) {
                msg.load(input);
        }

        // Construct the auth URL in a readable format
        String redirectUri = URLEncoder.encode(HOME_URL + "/.cdn-auth/callback", StandardCharsets.UTF_8);
        String authUrl = keycloakBaseUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/auth" +
                "?client_id=" + CLIENT_ID +
                "&response_type=code" +
                "&redirect_uri=" + redirectUri +
                "&scope=openid";

        // Replace variables in the template using msg
        String expectedHtml = templateContent
            .replace("${msg(\"redirectToAuthService\")}", msg.getProperty("redirectToAuthService"))
            .replace("${redirectFallbackDelay}", DEFAULT_CONFIG_MAP.get("Redirect Fallback Delay"))
            .replace("${authUrl}", authUrl)
            .replace("${msg(\"clickHereIfNoRedirect\")}", msg.getProperty("clickHereIfNoRedirect"))
            .replace("${redirectUriPath}", CloudFrontAuthProviderConfig.REDIRECT_URI_PATH)
            .replace("${redirectDelay}", DEFAULT_CONFIG_MAP.get("Redirect Delay"))
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
            .header("kc-realm-name", REALM_NAME)
            .header("kc-client-id", CLIENT_ID)
            .header("kc-client-secret", "WrongSecret")
            .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
            .when().get(CF_REDIRECT_403_URI)
            .then().statusCode(401)
            .extract().response();
    }


    // =====[ .cdn-auth/callback TESTS ]===== //
    @Test
    @DisplayName("Callback endpoint returns 400 when 'code' query param is missing")
    void testCallbackMissingCode() {
        given()
            .header("kc-realm-name", REALM_NAME)
            .header("kc-client-id", CLIENT_ID)
            .header("kc-client-secret", CLIENT_SECRET)
            .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
            .when().get(CALLBACK_URI)
            .then().statusCode(400)
            .extract().response();
    }

    @Test
    @DisplayName("Callback endpoint returns 401 when 'code' query param is invalid")
    void testCallbackInvalidCode() {
        given()
            .header("kc-realm-name", REALM_NAME)
            .header("kc-client-id", CLIENT_ID)
            .header("kc-client-secret", CLIENT_SECRET)
            .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
            .queryParam("original_uri", HOME_URL + "/")
            .queryParam("session_state", UUID.randomUUID().toString())
            .queryParam("iss", keycloakBaseUrl + "/realms/" + REALM_NAME)
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
            keycloakBaseUrl, REALM_NAME, HOME_URL, CLIENT_ID, USER_USERNAME_OK, USER_PASSWORD);
        assertNotNull(authorizationCode, "Authorization code should not be null");

        // Call the callback endpoint with the obtained code and validate CloudFront cookies are set
        Response callbackResponse = given()
                                    .header("kc-realm-name", REALM_NAME)
                                    .header("kc-client-id", CLIENT_ID)
                                    .header("kc-client-secret", CLIENT_SECRET)
                                    .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
                                    .queryParam("original_uri", HOME_URL + "/")
                                    .queryParam("session_state", UUID.randomUUID().toString())
                                    .queryParam("iss", keycloakBaseUrl + "/realms/" + REALM_NAME)
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

        getAdminClient().realm(REALM_NAME).keys().getKeyMetadata().getKeys();
        // Extract individual cookie values
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

        // Retrieve key metadata via admin client and extract certificate
        KeysMetadataRepresentation keyMetadata = getAdminClient().realm(REALM_NAME).keys().getKeyMetadata();
        PublicKey publicKey = null;
        if (keyMetadata != null && keyMetadata.getKeys() != null) {
            for (KeysMetadataRepresentation.KeyMetadataRepresentation k : keyMetadata.getKeys()) {
                if (k == null) continue;
                // Prefer ACTIVE RSA keys with algorithm RS256
                String status = k.getStatus();
                String algorithm = k.getAlgorithm();
                String ktype = k.getType();
                if (status != null && "ACTIVE".equalsIgnoreCase(status)
                    && algorithm != null && "RS256".equalsIgnoreCase(algorithm)
                    && ktype != null && "RSA".equalsIgnoreCase(ktype)) {
                    try {
                        String certB64 = k.getCertificate();
                        if (certB64 != null && !certB64.isEmpty()) {
                            // certificate is provided as base64 DER (no PEM headers)
                            byte[] certBytes = Base64.getDecoder().decode(certB64);
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                            publicKey = x509.getPublicKey();
                            break;
                        }

                        // Fallback to publicKey field (base64 encoded X.509 SubjectPublicKeyInfo)
                        String pubB64 = k.getPublicKey();
                        if (pubB64 != null && !pubB64.isEmpty()) {
                            byte[] pubBytes = Base64.getDecoder().decode(pubB64);
                            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            publicKey = kf.generatePublic(spec);
                            break;
                        }
                    } catch (Exception e) {
                        fail("Failed to extract public key from key metadata: " + e.getMessage());
                    }
                }
            }
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
    @DisplayName("Try get signed cookies with user without required role")
    void testGetSignedCookiesWithUserWithoutRequiredRole() throws IOException {
        // Get authorization code for user without required role
        String authorizationCode = KeycloakTestsTools.obtainAuthorizationCode(
            keycloakBaseUrl, REALM_NAME, HOME_URL, CLIENT_ID, USER_USERNAME_INVALID, USER_PASSWORD);
        assertNotNull(authorizationCode, "Authorization code should not be null");

        given()
            .header("kc-realm-name", REALM_NAME)
            .header("kc-client-id", CLIENT_ID)
            .header("kc-client-secret", CLIENT_SECRET)
            .header("kc-cf-sign-key-id", CF_SIGN_KEY_ID)
            .queryParam("original_uri", HOME_URL + "/")
            .queryParam("session_state", UUID.randomUUID().toString())
            .queryParam("iss", keycloakBaseUrl + "/realms/" + REALM_NAME)
            .queryParam("code", authorizationCode)
            .redirects().follow(false)
            .when().get(CALLBACK_URI)
            .then().statusCode(401)
            .extract().response();
    }
}
