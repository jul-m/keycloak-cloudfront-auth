package fr.julm.keycloak.providers.auth.cloudfront;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.Config;

public class CloudFrontAuthProviderConfig {
    // CONSTANTS CONFIG
    public static final String REDIRECT_URI_PATH = "/.cdn-auth/callback";
    
    // CONFIG PROPERTIES
    // spi-realm-restapi-extension-cloudfront-auth-redirect-delay
    private static final String CONF_REDIRECT_DELAY_NAME = "redirectDelay";
    private static final int CONF_REDIRECT_DELAY_DEFAULT = 0;
    
    // spi-realm-restapi-extension-cloudfront-auth-redirect-fallback-delay
    private static final String CONF_REDIRECT_FALLBACK_DELAY_NAME = "redirectFallbackDelay";
    private static final int CONF_REDIRECT_FALLBACK_DELAY_DEFAULT = 2;
    
    // spi-realm-restapi-extension-cloudfront-auth-display-request-id
    private static final String CONF_DISPLAY_REQUEST_ID_NAME = "displayRequestId";
    private static final boolean CONF_DISPLAY_REQUEST_ID_DEFAULT = true;
    
    // spi-realm-restapi-extension-cloudfront-auth-access-roles
    private static final String CONF_ACCESS_ROLES_NAME = "accessRoles";
    private static final String CONF_ACCESS_ROLES_DEFAULT = "cloudfront-access";
    private static final List<String> CONF_ACCESS_ROLES_DEFAULT_LIST = List.of(CONF_ACCESS_ROLES_DEFAULT.split(","));

    // spi-realm-restapi-extension-cloudfront-auth-auth-cookies-attributes
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_NAME = "authCookiesAttributes";
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT = "Path=/; Secure; HttpOnly";
    
    // LOADED CONFIG
    private static Integer redirectDelay = CONF_REDIRECT_DELAY_DEFAULT;
    private static Integer redirectFallbackDelay = CONF_REDIRECT_FALLBACK_DELAY_DEFAULT;
    private static Boolean displayRequestId = CONF_DISPLAY_REQUEST_ID_DEFAULT;
    private static List<String> accessRoles = CONF_ACCESS_ROLES_DEFAULT_LIST;
    private static String authCookiesAttributes = CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT;
    private static Map<String, String> allConfigsMap = null;

    private static final Logger logger = Logger.getLogger(CloudFrontAuthProviderConfig.class);

    public static void init(Config.Scope config) {
        logger.debugf(
            "Init - Default Config : " +
                "redirectDelay=%d, redirectFallbackDelay=%d, displayRequestId=%b, " +
                "accessRoles=%s, authCookiesAttributes=%s",
            CONF_REDIRECT_DELAY_DEFAULT, CONF_REDIRECT_FALLBACK_DELAY_DEFAULT, CONF_DISPLAY_REQUEST_ID_DEFAULT,
                 CONF_ACCESS_ROLES_DEFAULT, CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT
        );

        redirectDelay = config.getInt(CONF_REDIRECT_DELAY_NAME, CONF_REDIRECT_DELAY_DEFAULT);
        redirectFallbackDelay = config.getInt(CONF_REDIRECT_FALLBACK_DELAY_NAME, CONF_REDIRECT_FALLBACK_DELAY_DEFAULT);
        displayRequestId = config.getBoolean(CONF_DISPLAY_REQUEST_ID_NAME, CONF_DISPLAY_REQUEST_ID_DEFAULT);
        authCookiesAttributes = config.get(CONF_AUTH_COOKIES_ATTRIBUTES_NAME, CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT);

        // Don't include empty string, and use default list if empty
        accessRoles = Arrays.stream(
                    config.get(CONF_ACCESS_ROLES_NAME, CONF_ACCESS_ROLES_DEFAULT).split(",")
                ).filter(role -> !role.isEmpty())
                 .toList();

        if (accessRoles.isEmpty()) {
            accessRoles = CONF_ACCESS_ROLES_DEFAULT_LIST;
        }

        logger.debugf("Init - Loaded Config : "
            + "redirectDelay=%d, redirectFallbackDelay=%d, displayRequestId=%b, accessRoles=%s, "
            + "authCookiesAttributes=%s", redirectDelay,
            redirectFallbackDelay, displayRequestId, accessRoles, authCookiesAttributes);
    }

    public static Integer getRedirectToAuthDelaySec() {
        return redirectDelay;
    }

    public static Integer getRedirectToAuthFallbackDelaySec() {
        return redirectFallbackDelay;
    }

    public static Boolean displayRequestIdEnabled() {
        return displayRequestId;
    }

    public static List<String> getAccessRoles() {
        return accessRoles;
    }

    public static String getAuthCookiesAttributes() {
        return authCookiesAttributes;
    }

    public static Map<String, String> getAllConfigsMap() {
        if (allConfigsMap == null) {
            allConfigsMap = new HashMap<>();
            allConfigsMap.put("Redirect Delay", redirectDelay.toString());
            allConfigsMap.put("Redirect Fallback Delay", redirectFallbackDelay.toString());
            allConfigsMap.put("Display Request ID in Error Pages", displayRequestId.toString());
            allConfigsMap.put("Access Roles", "[" + String.join(", ", accessRoles) + "]");
            allConfigsMap.put("Auth Cookies Attributes", authCookiesAttributes);
        }
        return allConfigsMap;
    }
}
