package fr.julm.keycloak.providers.auth.cloudfront.it;

import io.github.cdimascio.dotenv.Dotenv;
import java.util.Map;

/**
 * Centralised constants for integration tests. Values are read from a project
 * `.env` file (docker/dev-tests/.env) when present; otherwise System environment
 * variables are used; otherwise sensible defaults.
 */
public final class ITEnvConfig {

    private static final Dotenv DOTENV;

    static {
        // Configure Dotenv to load docker/dev-tests/.env relative to project root if present.
        Dotenv d;
        try {
            d = Dotenv.configure()
                    .directory("docker/dev-tests")
                    .filename(".env")
                    .ignoreIfMalformed()
                    .ignoreIfMissing()
                    .load();
        } catch (Exception e) {
            d = null;
        }
        DOTENV = d;
    }

    private static String valueFor(String key, String defaultValue) {
        if (DOTENV != null) {
            String v = DOTENV.get(key);
            if (v != null) return v;
        }
        String env = System.getenv(key);
        return env != null ? env : defaultValue;
    }

    public static final String ADMIN_USERNAME = valueFor("KCA_KC_ADMIN_USER", "admin");
    public static final String ADMIN_PASSWORD = valueFor("KCA_KC_ADMIN_PASSWORD", "admin");
    public static final String REALM_NAME = valueFor("KCA_KC_REALM_NAME", "cloudfront-test");
    public static final String CLIENT_ID = valueFor("KCA_KC_CLIENT_ID", "cloudfront-test-client");
    public static final String CLIENT_SECRET = valueFor("KCA_KC_CLIENT_SECRET", "TestSecret123");

    // Keep these values hard-coded as requested
    public static final String USER_USERNAME_OK = "user1";
    public static final String USER_USERNAME_INVALID = "user2";
    public static final String USER_PASSWORD = "password123";
    public static final String LANG = "en";

    // CloudFront signing key id — can be provided through env file or env vars
    public static final String CF_SIGN_KEY_ID = valueFor("KCA_CF_SIGN_KEY_ID", "ABCDEFG");

    // Home URL: if KCA_APP_URL is provided use it, otherwise derive from openresty host port
    public static final String HOME_URL;
    static {
        String appUrl = valueFor("KCA_APP_URL", System.getenv("KCA_APP_URL"));
        if (appUrl != null && !appUrl.isBlank()) {
            HOME_URL = appUrl;
        } else {
            HOME_URL = "http://localhost:" + valueFor("KCA_OPENRESTY_HOST_PORT", "8081");
        }
    }

    // Default config map, with redirect delays optionally driven by env file or env vars
    public static final Map<String, String> PROVIDER_CFG = Map.of(
        "Auth Cookies Attributes", "Path=/; Secure; HttpOnly",
        "Access Roles", "[cloudfront-access]",
        "Display Request ID in Error Pages", "true",
        "Redirect Delay", valueFor("KCA_KC_AUTH_REDIRECT_DELAY", "1"),
        "Redirect Fallback Delay", valueFor("KCA_KC_AUTH_REDIRECT_FALLBACK_DELAY", "2")
    );

    private ITEnvConfig() {
        // utility class
    }
}
