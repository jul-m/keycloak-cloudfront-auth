package fr.julm.keycloak.providers.auth.cloudfront.test.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResourceProvider;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class CloudFrontAuthenticatorTest {

    @Mock
    private KeycloakSession keycloakSession;

    private CloudFrontAuthResourceProvider provider;

    @BeforeEach
    void setUp() {
        provider = new CloudFrontAuthResourceProvider(keycloakSession);
    }

    @Test
    void shouldImplementRealmResourceProvider() {
        assertThat(provider)
            .isInstanceOf(RealmResourceProvider.class);
    }

    @Test
    void shouldHaveKeycloakSession() {
        assertThat(provider)
            .hasFieldOrPropertyWithValue("session", keycloakSession);
    }
}
