package fr.julm.keycloak.providers.auth.cloudfront.it;

import static io.restassured.RestAssured.given;

import io.restassured.response.Response;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Small test utilities reused by integration tests.
 */
public final class KeycloakTestsTools {
    private KeycloakTestsTools() { }

    // Minimal browser-like flow to obtain an authorization code from Keycloak.
    public static String obtainAuthorizationCode(String keycloakBaseUrl, String realm, String homeUrl, String clientId, String username, String password) throws IOException {
        String authEndpoint = keycloakBaseUrl + "/realms/" + realm + "/protocol/openid-connect/auth";
        String redirectUri = homeUrl + "/.cdn-auth/callback";

        Response authResponse = given()
                .redirects().follow(false)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "openid")
                .when()
                .get(authEndpoint)
                .then()
                .extract()
                .response();

        String location = authResponse.getHeader("Location");
        String loginHtml;
        Map<String, String> loginCookies;
        String baseForRelative = keycloakBaseUrl;

        if (location != null) {
            Response loginPage = given().redirects().follow(false).when().get(location).then().statusCode(200).extract().response();
            loginHtml = loginPage.getBody().asString();
            loginCookies = loginPage.getCookies();
            try {
                java.net.URL url = new java.net.URL(location);
                baseForRelative = url.getProtocol() + "://" + url.getHost();
                if (url.getPort() != -1) baseForRelative += ":" + url.getPort();
            } catch (Exception ignored) { }
        } else {
            if (authResponse.getStatusCode() != 200) throw new IOException("Expected 200 or redirect for auth endpoint");
            loginHtml = authResponse.getBody().asString();
            loginCookies = authResponse.getCookies();
        }

        // Form action
        Pattern actionPattern = Pattern.compile("(?i)<form[^>]*action=\"([^\"]+)\"");
        Matcher actionMatcher = actionPattern.matcher(loginHtml);
        String formAction = actionMatcher.find() ? actionMatcher.group(1).replace("&amp;", "&") : authEndpoint;
        if (!formAction.startsWith("http")) {
            if (formAction.startsWith("/")) formAction = baseForRelative + formAction; else formAction = baseForRelative + "/" + formAction;
        }

        // collect inputs
        Pattern inputPattern = Pattern.compile("<input[^>]*name=[\"']([^\"']+)[\"'][^>]*?(?:value=[\"']?([^\"'>]*)[\"']?)?[^>]*>", Pattern.CASE_INSENSITIVE);
        Matcher inputMatcher = inputPattern.matcher(loginHtml);
        Map<String, String> formParams = new HashMap<>();
        while (inputMatcher.find()) formParams.put(inputMatcher.group(1), inputMatcher.groupCount() >= 2 && inputMatcher.group(2) != null ? inputMatcher.group(2) : "");

        formParams.put("username", username);
        formParams.put("password", password);
        formParams.putIfAbsent("login", "Sign In");

        // add query params from action
        try {
            java.net.URI actionUri = new java.net.URI(formAction);
            String query = actionUri.getRawQuery();
            if (query != null && !query.isEmpty()) {
                for (String p : query.split("&")) {
                    int idx = p.indexOf('=');
                    if (idx > 0) formParams.putIfAbsent(java.net.URLDecoder.decode(p.substring(0, idx), StandardCharsets.UTF_8.name()), java.net.URLDecoder.decode(p.substring(idx + 1), StandardCharsets.UTF_8.name()));
                    else formParams.putIfAbsent(java.net.URLDecoder.decode(p, StandardCharsets.UTF_8.name()), "");
                }
            }
        } catch (Exception ignored) { }

        Response postLogin = given()
                .cookies(loginCookies)
                .header("Referer", location != null ? location : authEndpoint)
                .header("Origin", baseForRelative)
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .formParams(formParams)
                .redirects().follow(false)
                .when()
                .post(formAction)
                .then()
                .extract()
                .response();

        String postLocation = postLogin.getHeader("Location");
        if (postLocation == null) {
            String body = postLogin.getBody().asString();
            // try meta refresh
            Matcher m = Pattern.compile("<meta[^>]+content=\"[^\"]*URL=([^\"]+)\"", Pattern.CASE_INSENSITIVE).matcher(body);
            String nextAuthUrl = m.find() ? m.group(1) : null;
            // fallback: look for links to the auth endpoint
            if (nextAuthUrl == null) {
                m = Pattern.compile("<a[^>]+href=\\\"([^\\\"]*protocol/openid-connect/auth[^\\\"]*)\\\"", Pattern.CASE_INSENSITIVE).matcher(body);
                if (m.find()) nextAuthUrl = m.group(1);
            }

            if (nextAuthUrl == null) throw new IOException("Login POST did not redirect and no auth URL found. status=" + postLogin.getStatusCode());
            if (nextAuthUrl.startsWith("/")) nextAuthUrl = baseForRelative + nextAuthUrl;
            Response followAuth = given().cookies(loginCookies).redirects().follow(false).when().get(nextAuthUrl).then().extract().response();
            postLocation = followAuth.getHeader("Location");
        }

        if (postLocation == null) throw new IOException("Login POST did not redirect to authorization callback.");

        Matcher codeMatcher = Pattern.compile("[\\?&]code=([^&]+)").matcher(postLocation);
        if (codeMatcher.find()) return URLDecoder.decode(codeMatcher.group(1), StandardCharsets.UTF_8.name());
        return null;
    }
}
