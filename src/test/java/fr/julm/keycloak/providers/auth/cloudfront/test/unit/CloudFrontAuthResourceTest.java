package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthResource;
import jakarta.ws.rs.core.Response;

@ExtendWith(MockitoExtension.class)
@PowerMockRunnerDelegate
@PrepareForTest(EventBuilder.class)
class CloudFrontAuthResourceTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private ThemeManager themeManager;

    @Mock
    private Theme theme;

    @Mock
    private KeycloakUriInfo uriInfo;

    @Mock
    private HttpClientProvider httpClientProvider;

    @Mock
    private AuthenticationManager authManager;

    @Mock
    private ClientConnection clientConnection;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    @Mock
    private ClientModel clientModel;

    @Mock
    private UserModel userModel;

    @Mock
    private KeycloakTransactionManager transactionManager;

    @Mock
    private EventBuilder eventBuilder;

    private CloudFrontAuthResource resource;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Setup basic mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getConnection()).thenReturn(clientConnection);
        lenient().when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");
        lenient().when(session.theme()).thenReturn(themeManager);
        lenient().when(themeManager.getTheme(any())).thenReturn(theme);
        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(realmProvider.getRealmByName(anyString())).thenReturn(realm);
        lenient().when(context.getUri()).thenReturn(uriInfo);
        lenient().when(uriInfo.getBaseUri()).thenReturn(new URI("https://auth.example.com/"));
        lenient().when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
        lenient().when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        lenient().when(session.getTransactionManager()).thenReturn(transactionManager);

        // Mock transaction manager methods
        doNothing().when(transactionManager).begin();
        doNothing().when(transactionManager).commit();
        doNothing().when(transactionManager).rollback();

        // Mock master realm
        RealmModel masterRealm = mock(RealmModel.class);
        lenient().when(realmProvider.getRealmByName("master")).thenReturn(masterRealm);
        lenient().when(masterRealm.getName()).thenReturn("master");

        // Mock event builder
        lenient().when(eventBuilder.realm(any(RealmModel.class))).thenReturn(eventBuilder);
        lenient().when(eventBuilder.client(any(String.class))).thenReturn(eventBuilder);
        lenient().when(eventBuilder.user(any(String.class))).thenReturn(eventBuilder);
        lenient().when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
        lenient().when(eventBuilder.event(any(EventType.class))).thenReturn(eventBuilder);
        lenient().when(eventBuilder.ipAddress(anyString())).thenReturn(eventBuilder);
        lenient().when(eventBuilder.getEvent()).thenReturn(mock(org.keycloak.events.Event.class));
        
        // Mock event builder send() method to use our mocked session
        doNothing().when(eventBuilder).error(anyString());
        doNothing().when(eventBuilder).success();

        // Mock EventBuilder constructor
        whenNew(EventBuilder.class).withArguments(any(RealmModel.class), any(KeycloakSession.class)).thenReturn(eventBuilder);

        // Create resource with mocked session
        resource = new CloudFrontAuthResource(session);
    }

    @Test
    void shouldHandleRedirect403() {
        // Given
        String realmName = "test-realm";
        String clientId = "test-client";
        String clientSecret = "test-secret";
        String cfSignKeyId = "test-key-id";
        String cfRequestId = "test-request-id";

        // When
        Response response = resource.handleRedirect403(
            realmName, clientId, clientSecret, cfSignKeyId, cfRequestId);

        // Then
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("text/html");
    }

    @Test
    void shouldHandleRedirect403WithMissingHeaders() {
        // Given
        String cfRequestId = "test-request-id";

        // When
        Response response = resource.handleRedirect403(
            null, null, "", null, cfRequestId);

        // Then
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getMediaType().toString()).isEqualTo("text/html");
    }

    @Test
    void shouldHandleCallback() {
        // Given
        String realmName = "test-realm";
        String clientId = "test-client";
        String clientSecret = "test-secret";
        String cfSignKeyId = "test-key-id";
        String cfRequestId = "test-request-id";
        String code = "test-code";
        String originalUri = "/test";

        // When
        Response response = resource.handleCallback(
            realmName, clientId, clientSecret, cfSignKeyId, cfRequestId, code, originalUri);

        // Then
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("text/html");
    }

    @Test
    void shouldHandleCallbackWithMissingHeaders() {
        // Given
        String cfRequestId = "test-request-id";
        String code = "test-code";
        String originalUri = "/test";

        // When
        Response response = resource.handleCallback(
            null, null, "", null, cfRequestId, code, originalUri);

        // Then
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getMediaType().toString()).isEqualTo("text/html");
    }

    @Test
    void shouldHandleCallbackWithInvalidCode() {
        // Given
        String realmName = "test-realm";
        String clientId = "test-client";
        String clientSecret = "test-secret";
        String cfSignKeyId = "test-key-id";
        String cfRequestId = "test-request-id";
        String code = "invalid-code";
        String originalUri = "/test";

        // When
        Response response = resource.handleCallback(
            realmName, clientId, clientSecret, cfSignKeyId, cfRequestId, code, originalUri);

        // Then
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getMediaType().toString()).isEqualTo("text/html");
    }
}
