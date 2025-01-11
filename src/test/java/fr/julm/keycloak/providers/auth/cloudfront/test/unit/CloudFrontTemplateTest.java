package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import java.net.URI;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.ThemeManager;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontTemplate;
import jakarta.ws.rs.core.Response;

@ExtendWith(MockitoExtension.class)
class CloudFrontTemplateTest {

    private CloudFrontTemplate template;

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private Theme theme;

    @Mock
    private ThemeManager themeManager;

    @Mock
    private RealmProvider realmProvider;

    @BeforeEach
    void setUp() throws Exception {
        // Setup basic mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.theme()).thenReturn(themeManager);
        lenient().when(themeManager.getTheme(eq(Theme.Type.LOGIN))).thenReturn(theme);
        lenient().when(theme.getMessages(any(Locale.class))).thenReturn(new Properties());
        lenient().when(theme.getName()).thenReturn("base");
        lenient().when(theme.getProperties()).thenReturn(new Properties());
        lenient().when(theme.getType()).thenReturn(Theme.Type.LOGIN);
        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(realmProvider.getRealmByName("master")).thenReturn(realm);
        lenient().when(context.resolveLocale(any())).thenReturn(Locale.ENGLISH);
        lenient().when(realm.getName()).thenReturn("master");
        lenient().when(realm.getDisplayName()).thenReturn("Master");
        
        // Setup URI info
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        lenient().when(context.getUri()).thenReturn(uriInfo);
        lenient().when(uriInfo.getBaseUri()).thenReturn(new URI("https://auth.example.com/"));

        // Create template
        template = new CloudFrontTemplate("error.ftl");
    }

    @Test
    void shouldThrowExceptionForInvalidTemplate() {
        // When/Then
        assertThatThrownBy(() -> new CloudFrontTemplate("invalid.ftl"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Error loading template invalid.ftl");
    }

    @Test
    void shouldRenderTemplate() {
        // Given
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("message", "errorTitle");

        // When
        String result = template.render(session, attributes);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).contains("<!DOCTYPE html>");
        assertThat(result).contains("<title>errorTitle</title>");
    }

    @Test
    void shouldServeTemplateResponse() {
        // Given
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("message", "errorTitle");

        // When
        Response response = template.serve(session, attributes, Response.Status.OK);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType()).isEqualTo(jakarta.ws.rs.core.MediaType.TEXT_HTML_TYPE);
    }

    @Test
    void shouldCreateBasicInternalServerErrorPage() {
        // When
        Response response = CloudFrontTemplate.basicInternalServerErrorPage();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getMediaType()).isEqualTo(jakarta.ws.rs.core.MediaType.TEXT_HTML_TYPE);
    }
}
