package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResourceProvider;
import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResourceProviderFactory;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthResourceProviderFactoryTest {

    private CloudFrontAuthResourceProviderFactory factory;

    @Mock
    private KeycloakSession session;

    @BeforeEach
    void setUp() {
        factory = new CloudFrontAuthResourceProviderFactory();
    }

    @Test
    void shouldCreateResourceProvider() {
        // When
        RealmResourceProvider provider = factory.create(session);

        // Then
        assertThat(provider).isNotNull();
        assertThat(provider).isInstanceOf(CloudFrontAuthResourceProvider.class);
    }

    @Test
    void shouldReturnCorrectId() {
        // When
        String id = factory.getId();

        // Then
        assertThat(id).isEqualTo("cloudfront-auth");
    }

    @Test
    void shouldCloseWithoutError() {
        // When/Then - should not throw any exception
        factory.close();
    }

    @Test
    void shouldInitializeWithoutError() {
        // Given
        Config.Scope config = mock(Config.Scope.class);

        // When/Then - should not throw any exception
        factory.init(config);
    }

    @Test
    void shouldPostInitializeWithoutError() {
        // When/Then - should not throw any exception
        factory.postInit(null);
    }

    @Test
    void shouldReturnOperationalInfo() {
        // When
        Map<String, String> info = factory.getOperationalInfo();

        // Then
        assertThat(info).isNotNull();
        assertThat(info).containsKey("Version");
        assertThat(info).containsKey("Redirect Delay");
        assertThat(info).containsKey("Redirect Failback Delay");
        assertThat(info).containsKey("Display Request ID in Error Pages");
        assertThat(info).containsKey("Access Roles");
        assertThat(info).containsKey("Auth Cookies Attributes");
    }
}
