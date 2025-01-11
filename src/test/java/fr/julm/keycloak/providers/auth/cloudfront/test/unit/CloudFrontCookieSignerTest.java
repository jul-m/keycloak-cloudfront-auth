package fr.julm.keycloak.providers.auth.cloudfront.test.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontCookieSigner;

@ExtendWith(MockitoExtension.class)
class CloudFrontCookieSignerTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private KeyManager keyManager;

    private KeyWrapper keyWrapper;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Setup basic mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);

        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        // Setup key wrapper
        keyWrapper = new KeyWrapper();
        keyWrapper.setKid("test-key-id");
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setType("RSA");
        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setPrivateKey(privateKey);
        keyWrapper.setPublicKey(publicKey);

        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256)))
            .thenReturn(keyWrapper);
    }

    @Test
    void shouldGenerateSignedCookies() {
        // Given
        Instant expiresAt = Instant.now().plusSeconds(3600);
        String keyPairId = "test-key-id";
        String resourceUrl = "https://example.com/test";

        // When
        String[] cookies = CloudFrontCookieSigner.generateSignedCookies(
            session, keyPairId, resourceUrl, expiresAt);

        // Then
        assertThat(cookies).hasSize(3);
        assertThat(cookies[0]).contains("CloudFront-Policy=");
        assertThat(cookies[1]).contains("CloudFront-Signature=");
        assertThat(cookies[2]).contains("CloudFront-Key-Pair-Id=" + keyPairId);
    }

    @Test
    void shouldThrowExceptionWhenNoSigningKeyFound() {
        // Given
        when(keyManager.getActiveKey(any(), any(), any())).thenReturn(null);

        // When/Then
        assertThatThrownBy(() -> CloudFrontCookieSigner.generateSignedCookies(
            session,
            "test-key-id",
            "https://example.com/test",
            Instant.now().plusSeconds(3600)
        )).isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to generate signed cookies")
            .hasRootCauseMessage("No active signing key found in realm");
    }
}
