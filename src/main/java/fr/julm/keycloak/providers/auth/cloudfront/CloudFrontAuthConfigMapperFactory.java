package fr.julm.keycloak.providers.auth.cloudfront;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.provider.ProviderFactory;

public class CloudFrontAuthConfigMapperFactory implements ProviderFactory<ProtocolMapper> {

    private static final CloudFrontAuthConfigMapper SINGLETON = new CloudFrontAuthConfigMapper();

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return CloudFrontAuthConfigMapper.PROVIDER_ID;
    }
}
