package fr.julm.keycloak.providers.auth.cloudfront;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CloudFrontAuthConfigMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-cloudfront-auth-config-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String PROPS_GROUP_JWTCOOKIE = "JWT Cookie";
    public static final String PROP_JWTCOOKIE_ENABLED = "jwt-cookie.enabled";
    public static final String PROP_JWTCOOKIE_ENABLED_DEFAULT = "false";
    public static final String PROP_JWTCOOKIE_NAME = "jwt-cookie.name";
    public static final String PROP_JWTCOOKIE_NAME_DEFAULT = "JwtAccessToken";
    public static final String PROP_JWTCOOKIE_ATTRIBUTES = "jwt-cookie.attributes";
    public static final String PROP_JWTCOOKIE_ATTRIBUTES_DEFAULT = "Path=/; Secure; HttpOnly";

    static {
        ProviderConfigProperty prop;
        
        prop = new ProviderConfigProperty();
        prop.setName(PROP_JWTCOOKIE_ENABLED);
        prop.setLabel(PROPS_GROUP_JWTCOOKIE + " - Enabled");
        prop.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        prop.setDefaultValue(PROP_JWTCOOKIE_ENABLED_DEFAULT);
        prop.setHelpText("If enabled, a cookie containing the JWT access token will be set in addition of CloudFront cookies.");
        configProperties.add(prop);
        
        prop = new ProviderConfigProperty();
        prop.setName(PROP_JWTCOOKIE_NAME);
        prop.setLabel(PROPS_GROUP_JWTCOOKIE + " - Cookie Name");
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        prop.setDefaultValue(PROP_JWTCOOKIE_NAME_DEFAULT);
        prop.setHelpText("Name of the cookie that will contain the JWT token.");
        configProperties.add(prop);
        
        prop = new ProviderConfigProperty();
        prop.setName(PROP_JWTCOOKIE_ATTRIBUTES);
        prop.setLabel(PROPS_GROUP_JWTCOOKIE + " - Cookie Attributes");
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        prop.setDefaultValue(PROP_JWTCOOKIE_ATTRIBUTES_DEFAULT);
        prop.setHelpText("Attributes to set on the JWT cookie.");
        configProperties.add(prop);
    }
    
    @Override
    public String getDisplayCategory() {
        return "Client Provider Config";
    }
    
    @Override
    public String getDisplayType() {
        return "CloudFront Auth Client Config";
    }
    
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    
    @Override
    public String getHelpText() {
        return "Configure CloudFront Auth Provider for this client.";
    }
    
    @Override
    public void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                          UserSessionModel userSession, KeycloakSession keycloakSession,
                          ClientSessionContext clientSessionCtx) {
        // Cette méthode est appelée lors de la création du token
        // Nous n'avons pas besoin d'ajouter de claim au token,
        // car ce mapper est uniquement utilisé pour la configuration
    }
    
    public static ProtocolMapperModel create(boolean enabled, String cookieName, String cookieAttributes) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(PROVIDER_ID);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        
        Map<String, String> config = new HashMap<>();
        config.put(PROP_JWTCOOKIE_ENABLED, String.valueOf(enabled));
        config.put(PROP_JWTCOOKIE_NAME, cookieName);
        config.put(PROP_JWTCOOKIE_ATTRIBUTES, cookieAttributes);
        
        mapper.setConfig(config);
        return mapper;
    }

    public static class CloudFrontAuthClientConfig {
        private boolean jwtCookieEnabled = Boolean.parseBoolean(PROP_JWTCOOKIE_ENABLED_DEFAULT);
        private String jwtCookieName = PROP_JWTCOOKIE_NAME_DEFAULT;
        private String jwtCookieAttributes = PROP_JWTCOOKIE_ATTRIBUTES_DEFAULT;

        public CloudFrontAuthClientConfig(AuthenticatedClientSessionModel clientSession) {
            clientSession.getClient().getProtocolMappersStream()
                .filter(mapper -> CloudFrontAuthConfigMapper.PROVIDER_ID.equals(mapper.getProtocolMapper()))
                .findFirst()
                .ifPresent(mapper -> {
                    Map<String, String> mapperConfig = mapper.getConfig();
                    this.jwtCookieEnabled = Boolean.parseBoolean(mapperConfig.get(PROP_JWTCOOKIE_ENABLED));
                    this.jwtCookieName = mapperConfig.get(PROP_JWTCOOKIE_NAME);
                    this.jwtCookieAttributes = mapperConfig.get(PROP_JWTCOOKIE_ATTRIBUTES);
                });
        }

        public boolean isJwtCookieEnabled() { return jwtCookieEnabled; }
        public String getJwtCookieName() { return jwtCookieName; }
        public String getJwtCookieAttributes() { return jwtCookieAttributes; }

        public String generateJwtCookie(String jwtAccessToken) {
            return String.format("%s=%s; %s", jwtCookieName, jwtAccessToken, jwtCookieAttributes);
        }

        public String showJwtCookieConfig() {
            if (jwtCookieEnabled) {
                return String.format("Enabled: '%b', Name: '%s', Attributes: '%s'",
                    jwtCookieEnabled, jwtCookieName, jwtCookieAttributes);
            }
            else {
                return String.format("Enabled: '%b'", jwtCookieEnabled);
            }
        }
    }
}
