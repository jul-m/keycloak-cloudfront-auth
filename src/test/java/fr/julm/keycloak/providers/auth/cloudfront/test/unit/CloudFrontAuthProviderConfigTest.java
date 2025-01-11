package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

import java.util.List;

import fr.julm.keycloak.providers.auth.cloudfront.test.util.TestUtils;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthProviderConfig;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthProviderConfigTest {

    // Load static properties from CloudFrontAuthProviderConfig
    private static final String CONF_REDIRECT_DELAY_NAME = getClassFieldString("CONF_REDIRECT_DELAY_NAME");
    private static final int CONF_REDIRECT_DELAY_DEFAULT = getClassFieldInteger("CONF_REDIRECT_DELAY_DEFAULT");
    private static final String CONF_REDIRECT_FAILBACK_DELAY_NAME = getClassFieldString("CONF_REDIRECT_FAILBACK_DELAY_NAME");
    private static final int CONF_REDIRECT_FAILBACK_DELAY_DEFAULT = getClassFieldInteger("CONF_REDIRECT_FAILBACK_DELAY_DEFAULT");
    private static final String CONF_DISPLAY_REQUEST_ID_NAME = getClassFieldString("CONF_DISPLAY_REQUEST_ID_NAME");
    private static final boolean CONF_DISPLAY_REQUEST_ID_DEFAULT = getClassFieldBoolean("CONF_DISPLAY_REQUEST_ID_DEFAULT");
    private static final String CONF_ACCESS_ROLES_NAME = getClassFieldString("CONF_ACCESS_ROLES_NAME");
    private static final String CONF_ACCESS_ROLES_DEFAULT = getClassFieldString("CONF_ACCESS_ROLES_DEFAULT");
    private static final List<String> CONF_ACCESS_ROLES_DEFAULT_LIST = List.of(CONF_ACCESS_ROLES_DEFAULT.split(","));
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_NAME = getClassFieldString("CONF_AUTH_COOKIES_ATTRIBUTES_NAME");
    private static final String CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT = getClassFieldString("CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT");

    @Mock
    private Config.Scope config;

    private static String getClassFieldString(String fieldName) {
        return TestUtils.getPrivateStaticField(CloudFrontAuthProviderConfig.class, fieldName, String.class);
    }

    private static Integer getClassFieldInteger(String fieldName) {
        return TestUtils.getPrivateStaticField(CloudFrontAuthProviderConfig.class, fieldName, Integer.class);
    }

    private static Boolean getClassFieldBoolean(String fieldName) {
        return TestUtils.getPrivateStaticField(CloudFrontAuthProviderConfig.class, fieldName, Boolean.class);
    }

    @BeforeEach
    void setUp() {
        // Setup default behavior for all config methods
        lenient().when(config.get(anyString())).thenReturn(null);
        lenient().when(config.getInt(anyString())).thenReturn(null);
        lenient().when(config.getBoolean(anyString())).thenReturn(null);
        
        // Reset to default values before each test
        CloudFrontAuthProviderConfig.init(config);
    }

    @Test
    void shouldUseDefaultValuesWhenConfigIsEmpty() {
        // When no config is provided, should use defaults
        assertThat(CloudFrontAuthProviderConfig.getRedirectToAuthDelaySec()).isEqualTo(CONF_REDIRECT_DELAY_DEFAULT);
        assertThat(CloudFrontAuthProviderConfig.getRedirectToAuthFailbackDelaySec()).isEqualTo(CONF_REDIRECT_FAILBACK_DELAY_DEFAULT);
        assertThat(CloudFrontAuthProviderConfig.displayRequestIdEnabled()).isEqualTo(CONF_DISPLAY_REQUEST_ID_DEFAULT);
        assertThat(CloudFrontAuthProviderConfig.getAccessRoles()).containsExactlyElementsOf(CONF_ACCESS_ROLES_DEFAULT_LIST);
        assertThat(CloudFrontAuthProviderConfig.getAuthCookiesAttributes()).isEqualTo(CONF_AUTH_COOKIES_ATTRIBUTES_DEFAULT);
    }

    @Test
    void shouldOverrideValuesFromConfig() {
        // Defined overrides
        int redirectDelay = 5;
        int redirectFailbackDelay = 10;
        boolean displayRequestId = false;
        String accessRoles = "role1,role2";
        String authCookiesAttributes = "Path=/custom; Secure";

        // Given
        lenient().when(config.getInt(CONF_REDIRECT_DELAY_NAME)).thenReturn(redirectDelay);
        lenient().when(config.getInt(CONF_REDIRECT_FAILBACK_DELAY_NAME)).thenReturn(redirectFailbackDelay);
        lenient().when(config.getBoolean(CONF_DISPLAY_REQUEST_ID_NAME)).thenReturn(displayRequestId);
        lenient().when(config.get(CONF_ACCESS_ROLES_NAME)).thenReturn(accessRoles);
        lenient().when(config.get(CONF_AUTH_COOKIES_ATTRIBUTES_NAME)).thenReturn(authCookiesAttributes);

        // When
        CloudFrontAuthProviderConfig.init(config);

        // Then
        assertThat(CloudFrontAuthProviderConfig.getRedirectToAuthDelaySec()).isEqualTo(redirectDelay);
        assertThat(CloudFrontAuthProviderConfig.getRedirectToAuthFailbackDelaySec()).isEqualTo(redirectFailbackDelay);
        assertThat(CloudFrontAuthProviderConfig.displayRequestIdEnabled()).isEqualTo(displayRequestId);
        assertThat(CloudFrontAuthProviderConfig.getAccessRoles()).containsExactlyElementsOf(List.of(accessRoles.split(",")));
        assertThat(CloudFrontAuthProviderConfig.getAuthCookiesAttributes()).isEqualTo(authCookiesAttributes);
    }

    @Test
    void shouldUseDefaultValueWhenAccessRolesListOfEmpty() {
        // Given
        String emptyAccessRoles = ",,,";
        lenient().when(config.get(CONF_ACCESS_ROLES_NAME)).thenReturn(emptyAccessRoles);

        // When
        CloudFrontAuthProviderConfig.init(config);

        // Then
        assertThat(CloudFrontAuthProviderConfig.getAccessRoles()).containsExactlyElementsOf(CONF_ACCESS_ROLES_DEFAULT_LIST);
    }

    @Test
    void shouldFilterEmptyAccessRoles() {
        // Given
        String rolesWithEmpty = "role1,,role2";
        lenient().when(config.get(CONF_ACCESS_ROLES_NAME)).thenReturn(rolesWithEmpty);

        // When
        CloudFrontAuthProviderConfig.init(config);

        // Then
        assertThat(CloudFrontAuthProviderConfig.getAccessRoles())
            .containsExactly("role1", "role2")
            .doesNotContain("")
            .hasSize(2);
    }
}
