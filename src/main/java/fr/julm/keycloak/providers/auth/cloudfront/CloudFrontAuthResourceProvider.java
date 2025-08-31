package fr.julm.keycloak.providers.auth.cloudfront;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class CloudFrontAuthResourceProvider implements RealmResourceProvider {
    private static final Logger logger = Logger.getLogger(CloudFrontAuthResourceProvider.class);
    private final KeycloakSession session;

    public CloudFrontAuthResourceProvider(KeycloakSession session) {
        logger.debugf("CloudFrontAuthResourceProvider - Initializing provider");
        this.session = session;
    }

    @Override
    public Object getResource() {
        logger.debugf("CloudFrontAuthResourceProvider - Creating new CloudFrontAuthResource");
        return new CloudFrontAuthResource(session);
    }

    @Override
    public void close() {
        logger.debugf("CloudFrontAuthResourceProvider - Closing provider");
    }
}
