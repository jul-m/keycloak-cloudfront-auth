package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthConfigMapper;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthConfigMapperTest {

    private CloudFrontAuthConfigMapper mapper;

    @Mock
    private KeycloakSession session;

    @Mock
    private UserSessionModel userSession;

    @Mock
    private ClientSessionContext clientSessionCtx;

    @Mock
    private IDToken token;

    @BeforeEach
    void setUp() {
        mapper = new CloudFrontAuthConfigMapper();
    }

    @Test
    void shouldReturnCorrectId() {
        // When
        String id = mapper.getId();

        // Then
        assertThat(id).isEqualTo(CloudFrontAuthConfigMapper.PROVIDER_ID);
    }

    @Test
    void shouldReturnCorrectDisplayType() {
        // When
        String displayType = mapper.getDisplayType();

        // Then
        assertThat(displayType).isEqualTo("CloudFront Auth Client Config");
    }

    @Test
    void shouldReturnCorrectDisplayCategory() {
        // When
        String category = mapper.getDisplayCategory();

        // Then
        assertThat(category).isEqualTo("Client Provider Config");
    }

    @Test
    void shouldReturnCorrectHelpText() {
        // When
        String helpText = mapper.getHelpText();

        // Then
        assertThat(helpText).isEqualTo("Configure CloudFront Auth Provider for this client.");
    }

    @Test
    void shouldReturnConfigProperties() {
        // When
        List<ProviderConfigProperty> properties = mapper.getConfigProperties();

        // Then
        assertThat(properties).isNotNull();
        assertThat(properties).hasSize(3);

        // Verify JWT Cookie Enabled property
        ProviderConfigProperty enabledProp = properties.get(0);
        assertThat(enabledProp.getName()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ENABLED);
        assertThat(enabledProp.getType()).isEqualTo(ProviderConfigProperty.BOOLEAN_TYPE);
        assertThat(enabledProp.getDefaultValue()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ENABLED_DEFAULT);

        // Verify JWT Cookie Name property
        ProviderConfigProperty nameProp = properties.get(1);
        assertThat(nameProp.getName()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_NAME);
        assertThat(nameProp.getType()).isEqualTo(ProviderConfigProperty.STRING_TYPE);
        assertThat(nameProp.getDefaultValue()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_NAME_DEFAULT);

        // Verify JWT Cookie Attributes property
        ProviderConfigProperty attrProp = properties.get(2);
        assertThat(attrProp.getName()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ATTRIBUTES);
        assertThat(attrProp.getType()).isEqualTo(ProviderConfigProperty.STRING_TYPE);
        assertThat(attrProp.getDefaultValue()).isEqualTo(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ATTRIBUTES_DEFAULT);
    }

    @Test
    void shouldCreateMapperModel() {
        // Given
        boolean enabled = true;
        String cookieName = "testCookie";
        String cookieAttributes = "Path=/test; Secure";

        // When
        ProtocolMapperModel model = CloudFrontAuthConfigMapper.create(enabled, cookieName, cookieAttributes);

        // Then
        assertThat(model).isNotNull();
        assertThat(model.getName()).isEqualTo(CloudFrontAuthConfigMapper.PROVIDER_ID);
        assertThat(model.getProtocolMapper()).isEqualTo(CloudFrontAuthConfigMapper.PROVIDER_ID);
        assertThat(model.getProtocol()).isEqualTo("openid-connect");

        assertThat(model.getConfig()).containsEntry(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ENABLED, "true");
        assertThat(model.getConfig()).containsEntry(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_NAME, cookieName);
        assertThat(model.getConfig()).containsEntry(CloudFrontAuthConfigMapper.PROP_JWTCOOKIE_ATTRIBUTES, cookieAttributes);
    }

    @Test
    void shouldSetClaimWithoutError() {
        // Given
        ProtocolMapperModel mappingModel = mock(ProtocolMapperModel.class);

        // When/Then - should not throw any exception or modify the token
        mapper.setClaim(token, mappingModel, userSession, session, clientSessionCtx);
    }
}
