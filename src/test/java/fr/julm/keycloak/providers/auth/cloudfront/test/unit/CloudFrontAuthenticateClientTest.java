package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthenticateClient;
import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthProviderConfig;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;

import java.net.URI;

@ExtendWith(MockitoExtension.class)
class CloudFrontAuthenticateClientTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private RealmModel realm;

    @Mock
    private RealmModel masterRealm;

    @Mock
    private ClientModel client;

    private static final String REALM_NAME = "test-realm";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String LOG_PREFIX = "TEST";
    private static final String AUTH_SERVER_URL = "https://auth.example.com/";

    @BeforeEach
    void setUp() throws Exception {
        // Setup basic mocks that most tests will need
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getAuthServerUrl()).thenReturn(URI.create(AUTH_SERVER_URL));
        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(realmProvider.getRealmByName(REALM_NAME)).thenReturn(realm);
        lenient().when(realmProvider.getRealmByName("master")).thenReturn(masterRealm);
        lenient().when(realm.getClientByClientId(CLIENT_ID)).thenReturn(client);
        lenient().when(client.isEnabled()).thenReturn(true);
        lenient().when(client.isStandardFlowEnabled()).thenReturn(true);
        lenient().when(client.validateSecret(CLIENT_SECRET)).thenReturn(true);
        lenient().when(client.getRootUrl()).thenReturn("https://example.com");
        lenient().when(client.getBaseUrl()).thenReturn("");
    }

    @Test
    void shouldInitializeClientSuccessfully() {
        // When
        CloudFrontAuthenticateClient authenticateClient = new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        );

        // Then
        assertThat(authenticateClient.realm).isEqualTo(realm);
        assertThat(authenticateClient.client).isEqualTo(client);
        assertThat(authenticateClient.authEndpoint)
            .isEqualTo(AUTH_SERVER_URL + "realms/" + REALM_NAME + "/protocol/openid-connect/auth");
        assertThat(authenticateClient.tokenEndpoint)
            .isEqualTo(AUTH_SERVER_URL + "realms/" + REALM_NAME + "/protocol/openid-connect/token");
        assertThat(authenticateClient.rootUrl)
            .isEqualTo("https://example.com");
        assertThat(authenticateClient.redirectUri)
            .isEqualTo("https://example.com" + CloudFrontAuthProviderConfig.REDIRECT_URI_PATH);
    }

    @Test
    void shouldThrowExceptionWhenRealmNotFound() {
        // Given
        when(realmProvider.getRealmByName(REALM_NAME)).thenReturn(null);

        // Then
        assertThatThrownBy(() -> new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        ))
            .isInstanceOf(WebApplicationException.class)
            .matches(e -> ((WebApplicationException) e).getResponse().getStatus() == Response.Status.BAD_REQUEST.getStatusCode())
            .matches(e -> ((WebApplicationException) e).getResponse().getEntity().equals("Realm not found"));
    }

    @Test
    void shouldThrowExceptionWhenClientNotFound() {
        // Given
        when(realm.getClientByClientId(CLIENT_ID)).thenReturn(null);

        // Then
        assertThatThrownBy(() -> new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        ))
            .isInstanceOf(WebApplicationException.class)
            .matches(e -> ((WebApplicationException) e).getResponse().getStatus() == Response.Status.BAD_REQUEST.getStatusCode())
            .matches(e -> ((WebApplicationException) e).getResponse().getEntity().equals("Client not found"));
    }

    @Test
    void shouldThrowExceptionWhenClientDisabled() {
        // Given
        when(client.isEnabled()).thenReturn(false);

        // Then
        assertThatThrownBy(() -> new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        ))
            .isInstanceOf(WebApplicationException.class)
            .matches(e -> ((WebApplicationException) e).getResponse().getStatus() == Response.Status.BAD_REQUEST.getStatusCode())
            .matches(e -> ((WebApplicationException) e).getResponse().getEntity().equals("Client is disabled"));
    }

    @Test
    void shouldThrowExceptionWhenStandardFlowDisabled() {
        // Given
        when(client.isStandardFlowEnabled()).thenReturn(false);

        // Then
        assertThatThrownBy(() -> new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        ))
            .isInstanceOf(WebApplicationException.class)
            .matches(e -> ((WebApplicationException) e).getResponse().getStatus() == Response.Status.BAD_REQUEST.getStatusCode())
            .matches(e -> ((WebApplicationException) e).getResponse().getEntity().equals("Standard flow not enabled"));
    }

    @Test
    void shouldThrowExceptionWhenInvalidClientSecret() {
        // Given
        when(client.validateSecret(CLIENT_SECRET)).thenReturn(false);

        // Then
        assertThatThrownBy(() -> new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        ))
            .isInstanceOf(WebApplicationException.class)
            .matches(e -> ((WebApplicationException) e).getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode())
            .matches(e -> ((WebApplicationException) e).getResponse().getEntity().equals("Invalid client credentials"));
    }

    @Test
    void shouldHandleEmptyRootUrl() {
        // Given
        when(client.getRootUrl()).thenReturn("");

        // When
        CloudFrontAuthenticateClient authenticateClient = new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        );

        // Then
        assertThat(authenticateClient.rootUrl).isEqualTo("undefined");
    }

    @Test
    void shouldHandleRootUrlWithTrailingSlash() {
        // Given
        when(client.getRootUrl()).thenReturn("https://example.com/");

        // When
        CloudFrontAuthenticateClient authenticateClient = new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        );

        // Then
        assertThat(authenticateClient.rootUrl).isEqualTo("https://example.com");
    }

    @Test
    void shouldUseBaseUrlForHomeUrlWhenProvided() {
        // Given
        when(client.getBaseUrl()).thenReturn("https://example.com/app");

        // When
        CloudFrontAuthenticateClient authenticateClient = new CloudFrontAuthenticateClient(
            session, REALM_NAME, CLIENT_ID, CLIENT_SECRET, LOG_PREFIX
        );

        // Then
        assertThat(authenticateClient.homeUrl).isEqualTo("https://example.com/app");
    }
}
