package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResource;
import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResourceProvider;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthResourceProviderTest {

    private CloudFrontAuthResourceProvider provider;

    @Mock
    private KeycloakSession session;

    @BeforeEach
    void setUp() {
        provider = new CloudFrontAuthResourceProvider(session);
    }

    @Test
    void shouldReturnCloudFrontAuthResource() {
        // When
        Object resource = provider.getResource();

        // Then
        assertThat(resource).isNotNull();
        assertThat(resource.getClass()).isEqualTo(CloudFrontAuthResource.class);
    }

    @Test
    void shouldCloseWithoutError() {
        // When/Then - should not throw any exception
        provider.close();
    }
}
