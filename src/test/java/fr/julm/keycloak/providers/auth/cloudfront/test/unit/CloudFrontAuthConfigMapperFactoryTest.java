package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.ProtocolMapper;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthConfigMapper;
import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthConfigMapperFactory;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthConfigMapperFactoryTest {

    private CloudFrontAuthConfigMapperFactory factory;

    @Mock
    private KeycloakSession session;

    @BeforeEach
    void setUp() {
        factory = new CloudFrontAuthConfigMapperFactory();
    }

    @Test
    void shouldCreateMapper() {
        // When
        ProtocolMapper mapper = factory.create(session);

        // Then
        assertThat(mapper).isNotNull();
        assertThat(mapper.getClass()).isEqualTo(CloudFrontAuthConfigMapper.class);
    }

    @Test
    void shouldReturnCorrectId() {
        // When
        String id = factory.getId();

        // Then
        assertThat(id).isEqualTo("oidc-cloudfront-auth-config-mapper");
    }

    @Test
    void shouldCloseWithoutError() {
        // When/Then - should not throw any exception
        factory.close();
    }

    @Test
    void shouldInitializeWithoutError() {
        // When/Then - should not throw any exception
        factory.init(null);
    }

    @Test
    void shouldPostInitializeWithoutError() {
        // When/Then - should not throw any exception
        factory.postInit(null);
    }
}
