package fr.julm.keycloak.providers.auth.cloudfront;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeyManager;
import org.keycloak.models.RealmModel;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.Algorithm;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;

public class CloudFrontCookieSigner {
    private static final String COOKIE_POLICY = "CloudFront-Policy";
    private static final String COOKIE_SIGNATURE = "CloudFront-Signature";
    private static final String COOKIE_KEY_PAIR_ID = "CloudFront-Key-Pair-Id";

    private static final Logger logger = Logger.getLogger(CloudFrontCookieSigner.class);
    private static final Map<RealmModel, KeyWrapper> signingKeysCache = new ConcurrentHashMap<>();

    private static KeyWrapper getSigningKey(KeycloakSession session) {
        logger.debugf("CloudFrontCookieSigner - Getting signing key");
        RealmModel realm = session.getContext().getRealm();

        return signingKeysCache.computeIfAbsent(realm, k -> {
            // Get the active signing key from the realm
            KeyManager keyManager = session.keys();
            KeyWrapper key = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
            if (key == null) {
                logger.errorf("CloudFrontCookieSigner - Signing key not found");
                throw new RuntimeException("No active signing key found in realm");
            }
            return key;
        });
    }

    private static PrivateKey getPrivateKey(KeycloakSession session) {
        KeyWrapper key = getSigningKey(session);
        return (PrivateKey) key.getPrivateKey();
    }

    /**
     * Converts the given data to be safe for use in signed URLs for a private
     * distribution by using specialized Base64 encoding.
     * @implSpec Code from aws-sdk-java-v2: https://github.com/aws/aws-sdk-java-v2/blob/2.29.49/services/cloudfront/src/main/java/software/amazon/awssdk/services/cloudfront/internal/utils/SigningUtils.java#L98
     */
    private static String makeBytesUrlSafe(byte[] bytes) {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        for (int i = 0; i < encoded.length; i++) {
            switch (encoded[i]) {
                case '+':
                    encoded[i] = '-';
                    continue;
                case '=':
                    encoded[i] = '_';
                    continue;
                case '/':
                    encoded[i] = '~';
                    continue;
                default:
            }
        }
        return new String(encoded, StandardCharsets.UTF_8);
    }

    /**
     * Signs the data given with the private key given, using the SHA1withRSA algorithm provided by bouncy castle.
     * Return result as Base64 encoded string in CloudFront safe-url format.
     * @implSpec Adapted from signWithSha1Rsa() function from aws-sdk-java-v2:
     * https://github.com/aws/aws-sdk-java-v2/blob/2.29.49/services/cloudfront/src/main/java/software/amazon/awssdk/services/cloudfront/internal/utils/SigningUtils.java#L129C26-L129C41
     */
    private static String getEncodedSignature(String dataToSign, PrivateKey privateKey) throws InvalidKeyException {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            SecureRandom random = new SecureRandom();
            signature.initSign(privateKey, random);
            signature.update(dataToSign.getBytes(StandardCharsets.UTF_8));

            return makeBytesUrlSafe(signature.sign());
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a custom policy for the given parameters.
     * For more information, see <a href=
     * "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html"
     * >Creating a signed URL using a custom policy</a>
     * or
     * <a href=
     * "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-custom-policy.html"
     * >Setting signed cookies using a custom policy</a>.
     * @implSpec Adapted from aws-sdk-java-v2: https://github.com/aws/aws-sdk-java-v2/blob/2.29.49/services/cloudfront/src/main/java/software/amazon/awssdk/services/cloudfront/internal/utils/SigningUtils.java#L73
     */
    private static String buildCustomPolicy(
        String resourceUrl, Instant expirationDate, String ipAddress, Integer activeDate
    ) {
        return "{\"Statement\":[{"
                + "\"Resource\":\"" + resourceUrl + "\""
                + ",\"Condition\":{"
                + "\"DateLessThan\":{\"AWS:EpochTime\":" + expirationDate.getEpochSecond() + "}"
                + (ipAddress == null
                    ? ""
                    : ",\"IpAddress\":{\"AWS:SourceIp\":\"" + ipAddress + "\"}"
                )
                + (activeDate == null
                    ? ""
                    : ",\"DateGreaterThan\":{\"AWS:EpochTime\":" + activeDate + "}"
                )
                + "}}]}";
    }

    private static String[] getSignedCookies(
        PrivateKey privateKey, String keyId, String resource, Instant expiration, String ipAddress, Integer activeDate
    ) throws InvalidKeyException {
        String customPolicy = buildCustomPolicy(resource, expiration, ipAddress, activeDate);
        String customPolicySignature = getEncodedSignature(customPolicy, privateKey);
        String encodedCustomPolicy = makeBytesUrlSafe(customPolicy.getBytes(StandardCharsets.UTF_8));
        return new String[] {
            generateCookie(COOKIE_POLICY, encodedCustomPolicy),
            generateCookie(COOKIE_SIGNATURE, customPolicySignature),
            generateCookie(COOKIE_KEY_PAIR_ID, keyId)
        };
    }

    private static String generateCookie(String name, String value) {
        return String.format("%s=%s; %s", name, value, CloudFrontAuthProviderConfig.getAuthCookiesAttributes());
    }

    
    public static String[] generateSignedCookies(
        KeycloakSession session, String keyId, String resource, Instant expiration
    ) {
        logger.debugf(
            "CloudFrontCookieSigner - Generating signed cookies [keyId=%s, resource=%s, expiration=%d]",
            keyId, resource, expiration
        );
        
        try {
            PrivateKey privateKey = getPrivateKey(session);
            if (privateKey == null) {
                logger.errorf(
                    "CloudFrontCookieSigner - Failed to load signing key [keyId=%s]", keyId
                );
                throw new RuntimeException("No private key available");
            }

            String[] signedCookies = getSignedCookies(
                privateKey, keyId, resource, expiration, null, null
            );

            logger.debugf(
                "CloudFrontCookieSigner - Generated cookies successfully [keyId=%s, resource=%s, expiration=%d]",
                keyId, resource, expiration
            );

            return signedCookies;

        } catch (Exception e) {
            logger.error("CloudFrontCookieSigner - Error generating signed cookies", e);
            throw new RuntimeException("Failed to generate signed cookies", e);
        }
    }
}
