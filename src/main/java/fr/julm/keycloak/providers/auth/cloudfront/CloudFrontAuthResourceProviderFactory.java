package fr.julm.keycloak.providers.auth.cloudfront;

import java.util.Map;
import java.util.HashMap;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class CloudFrontAuthResourceProviderFactory
    implements RealmResourceProviderFactory, ServerInfoAwareProviderFactory
{
    public static final String PROVIDER_ID = "cloudfront-auth";
    public static final String VERSION = CloudFrontAuthResourceProviderFactory
                                            .class.getPackage()
                                            .getImplementationVersion();

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new CloudFrontAuthResourceProvider(session);
    }

    @Override
    public void init(Scope config) {
        CloudFrontAuthProviderConfig.init(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("Version", VERSION);
        info.put("Redirect Delay", CloudFrontAuthProviderConfig.getRedirectToAuthDelaySec().toString());
        info.put("Redirect Fallback Delay", CloudFrontAuthProviderConfig.getRedirectToAuthFallbackDelaySec().toString());
        info.put("Display Request ID in Error Pages", CloudFrontAuthProviderConfig.displayRequestIdEnabled().toString());
        info.put("Access Roles", "[" + String.join(", ", CloudFrontAuthProviderConfig.getAccessRoles()) + "]");
        info.put("Auth Cookies Attributes", CloudFrontAuthProviderConfig.getAuthCookiesAttributes());
        return info;
    }
}
