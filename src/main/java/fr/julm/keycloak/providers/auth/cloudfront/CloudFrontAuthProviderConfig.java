package fr.julm.keycloak.providers.auth.cloudfront;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config;

public class CloudFrontAuthProviderConfig {
    // CONSTANTS CONFIG
    public static final String REDIRECT_URI_PATH = "/.cdn-auth/callback";
    
    // CONFIG PROPERTIES
    // spi-realm-restapi-extension-cloudfront-auth-redirect-delay
    private static final String CONF_REDIRECT_DELAY_NAME = "redirectDelay";
    private static final int CONF_REDIRECT_DELAY_DEFAULT = 0;
    
    // spi-realm-restapi-extension-cloudfront-auth-redirect-failback-delay
    private static final String CONF_REDIRECT_FAILBACK_DELAY_NAME = "redirectFailbackDelay";
    private static final int CONF_REDIRECT_FAILBACK_DELAY_DEFAULT = 2;
    
    // spi-realm-restapi-extension-cloudfront-auth-display-request-id
    private static final String CONF_DISPLAY_REQUEST_ID_NAME = "displayRequestId";
    private static final boolean CONF_DISPLAY_REQUEST_ID_DEFAULT = true;
    
    // spi-realm-restapi-extension-cloudfront-auth-access-roles
    private static final String CONF_ACCESS_ROLES_NAME = "accessRoles";
    private static final String CONF_ACCESS_ROLES_DEFAULT = "cloudfront-access";

    // spi-realm-restapi-extension-cloudfront-auth-auth-cookies-attributes
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_NAME = "authCookiesAttributes";
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT = "Path=/; Secure; HttpOnly";
    
    // LOADED CONFIG
    private static Integer redirectDelay = CONF_REDIRECT_DELAY_DEFAULT;
    private static Integer redirectFailbackDelay = CONF_REDIRECT_FAILBACK_DELAY_DEFAULT;
    private static Boolean displayRequestId = CONF_DISPLAY_REQUEST_ID_DEFAULT;
    private static List<String> accessRoles = List.of(CONF_ACCESS_ROLES_DEFAULT);
    private static String authCookiesAttributes = CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT;

    private static final Logger logger = Logger.getLogger(CloudFrontAuthProviderConfig.class);

    public static void init(Config.Scope config) {
        logger.debugf(
            "Init - Default/Current Config : " +
                "redirectDelay=%d, redirectFailbackDelay=%d, displayRequestId=%b, accessRoles=%s, authCookiesAttributes=%s",
            redirectDelay, redirectFailbackDelay, displayRequestId, accessRoles, authCookiesAttributes);
        
        if (config.get(CONF_REDIRECT_DELAY_NAME) != null) {
            redirectDelay = config.getInt(CONF_REDIRECT_DELAY_NAME);
        }
        if (config.get(CONF_REDIRECT_FAILBACK_DELAY_NAME) != null) {
            redirectFailbackDelay = config.getInt(CONF_REDIRECT_FAILBACK_DELAY_NAME);
        }
        if (config.get(CONF_DISPLAY_REQUEST_ID_NAME) != null) {
            displayRequestId = config.getBoolean(CONF_DISPLAY_REQUEST_ID_NAME);
        }
        if (config.get(CONF_ACCESS_ROLES_NAME) != null) {
            accessRoles = List.of(config.get(CONF_ACCESS_ROLES_NAME).split(","));
        }
        if (config.get(CONF_AUTH_COOKIES_ATTRIBUTES_NAME) != null) {
            authCookiesAttributes = config.get(CONF_AUTH_COOKIES_ATTRIBUTES_NAME);
        }

        logger.debugf("Init - Loaded Config : "
                + "redirectDelay=%d, redirectFailbackDelay=%d, displayRequestId=%b, accessRoles=%s, authCookiesAttributes=%s",
            redirectDelay, redirectFailbackDelay, displayRequestId, accessRoles, authCookiesAttributes);
    }

    public static Integer getRedirectToAuthDelaySec() {
        return redirectDelay;
    }

    public static Integer getRedirectToAuthFailbackDelaySec() {
        return redirectFailbackDelay;
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
}
