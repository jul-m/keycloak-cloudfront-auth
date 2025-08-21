package fr.julm.keycloak.providers.auth.cloudfront.it;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;

/**
 * Outils de test pour vérifier les signatures CloudFront et les cookies signés.
 *
 * Hypothèses raisonnables prises:
 * - La clé publique est fournise en tant que java.security.PublicKey.
 * - La signature CloudFront utilise SHA1withRSA (conforme au code Lua fourni).
 * - Le cookie Policy est encodé en base64url (remplacements -/_ et padding absent possible).
 * - Le Key-Pair-Id attendu peut être vérifié si la variable d'environnement KC_CF_SIGN_KEY_ID est définie;
 *   sinon la vérification du Key-Pair-Id est considérée comme non-applicable (ok).
 */
public final class CloudFrontAuthTools {


    private static final Logger LOGGER = Logger.getLogger(CloudFrontAuthTools.class.getName());

    private CloudFrontAuthTools() { /* util */ }

    /**
     * Vérifie une signature CloudFront sur la policy donnée.
     * @param publicKey clé publique RSA
     * @param policy policy (texte JSON) utilisée pour la vérification (doit être la policy décodée, non re-encodée)
     * @param signatureBase64Url signature encodée en base64url (CloudFront URL-safe)
     * @return true si la signature est valide, false sinon
     */
    public static boolean checkCloudFrontSignature(PublicKey publicKey, String policy, String signatureBase64Url) {
        if (publicKey == null || policy == null || signatureBase64Url == null) return false;

        try {
            byte[] signatureBytes = decodeBase64Url(signatureBase64Url);
            if (signatureBytes == null) return false;

            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(publicKey);
            sig.update(policy.getBytes(StandardCharsets.UTF_8));
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            // En contexte de test, on retourne false sur toute exception
            return false;
        }
    }

    /**
     * Vérifie les 3 cookies CloudFront: Policy, Key-Pair-Id et Signature.
     * Retourne un objet Result contenant les détails (signature ok, expiration, correspondance KeyPairId, etc.).
     *
     * @param publicKey clé publique RSA
     * @param cookiePolicy valeur du cookie CloudFront-Policy (base64url)
     * @param cookieKeyPairId valeur du cookie CloudFront-Key-Pair-Id
     * @param cookieSignature valeur du cookie CloudFront-Signature (base64url)
     * @return Result avec le statut des différentes vérifications
     */
    public static Result checkCloudFrontSignedCookies(
        PublicKey publicKey, String cookiePolicy, String cookieKeyPairId, String cookieSignature
    ) {
        Result r = new Result();

        if (publicKey == null) {
            r.isAuthenticated = false;
            r.signatureValid = false;
            r.error = "publicKey is null";
            LOGGER.warning("checkCloudFrontSignedCookies: publicKey is null");
            return r;
        }

        if (cookiePolicy == null || cookieKeyPairId == null || cookieSignature == null) {
            r.isAuthenticated = false;
            r.signatureValid = false;
            r.error = "Missing one or more required cookies";

            LOGGER.warning(
                "checkCloudFrontSignedCookies: missing cookie(s) - policy=" + (cookiePolicy!=null) +
                " keyPairId=" + (cookieKeyPairId!=null) + " signature=" + (cookieSignature!=null));
            return r;
        }

        // Décoder la policy base64url
        byte[] policyBytes = decodeBase64Url(cookiePolicy);
        if (policyBytes == null) {
            r.isAuthenticated = false;
            r.signatureValid = false;
            r.error = "Failed to decode policy base64url";
            LOGGER.warning("checkCloudFrontSignedCookies: failed to base64url-decode policy cookie");
            return r;
        }

        String policy = new String(policyBytes, StandardCharsets.UTF_8);
        r.rawPolicy = policy;

        // Vérifier expiration (chercher AWS:EpochTime dans le JSON de la policy)
        Long epoch = extractEpochTime(policy);
        if (epoch != null) {
            long now = Instant.now().getEpochSecond();
            r.expirationEpoch = epoch;
            r.expired = now >= epoch;
            if (r.expired) {
                LOGGER.warning(
                    "checkCloudFrontSignedCookies: policy expired (expirationEpoch=" + r.expirationEpoch + ")");
            }
        } else {
            r.expirationEpoch = null;
            r.expired = false; // si non trouvée, on ne considère pas comme expired mais on note l'absence
            r.warning = "Expiration not found in policy";
            LOGGER.fine("checkCloudFrontSignedCookies: expiration not found in policy JSON");
        }

        // Vérifier signature
        r.signatureValid = checkCloudFrontSignature(publicKey, policy, cookieSignature);
        if (!r.signatureValid) {
            LOGGER.warning(
                "checkCloudFrontSignedCookies: signature verification failed (policy length=" + 
                (policy==null?0:policy.length()) + ")");
        }

        // Vérifier Key-Pair-Id si variable d'env attendue définie (utilise la constante de test)
        String expectedKeyPairId = ITEnvConfig.CF_SIGN_KEY_ID;
        if (expectedKeyPairId != null && !expectedKeyPairId.isEmpty()) {
            r.keyPairIdMatch = expectedKeyPairId.equals(cookieKeyPairId);
            if (!r.keyPairIdMatch) {
                LOGGER.warning("checkCloudFrontSignedCookies: keyPairId mismatch, expected='" + 
                expectedKeyPairId + "' got='" + cookieKeyPairId + "'");
            }
        } else {
            r.keyPairIdMatch = null; // indéterminé
        }

        // Déterminer isAuthenticated: signature valide && non expiré && (keyPairId ok ou indéterniné)
        boolean keyOk = (r.keyPairIdMatch == null) || (r.keyPairIdMatch.booleanValue());
        r.isAuthenticated = r.signatureValid && !r.expired && keyOk;

        // Construire message d'erreur agrégé
        if (!r.signatureValid) r.error = (r.error == null ? "Invalid signature" : r.error + "; Invalid signature");
        if (r.expired) r.error = (r.error == null ? "Policy expired" : r.error + "; Policy expired");
        if (r.keyPairIdMatch != null && !r.keyPairIdMatch) r.error = (
            r.error == null ? "KeyPairId mismatch" : r.error + "; KeyPairId mismatch");

        return r;
    }

    private static byte[] decodeBase64Url(String s) {
        if (s == null) return null;
        String original = s;
        String t = s.trim();
        // Remove surrounding quotes if present
        if (t.startsWith("\"") && t.endsWith("\"")) {
            t = t.substring(1, t.length() - 1);
        }
        // If URL-encoded characters present, try URL-decode first
        try {
            if (t.indexOf('%') >= 0) {
                t = java.net.URLDecoder.decode(t, StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException e) {
            // ignore and continue with original
        }

        // Remove whitespace and any characters that are not valid Base64/url chars
        t = t.replaceAll("\\s+", "");
        // Allow CloudFront's custom URL-safe characters including '~'
        t = t.replaceAll("[^A-Za-z0-9_\\-\\+\\/=~]", "");

        // Map URL-safe variants to the server-side custom mapping used in Lua:
        // '-' -> '+' , '_' -> '=' , '~' -> '/'
        String std = t.replace('-', '+')
            .replace('_', '=')
            .replace('~', '/');

        // Ensure padding for standard form
        int rem = std.length() % 4;
        if (rem != 0) {
            int pad = 4 - rem;
            std += "=".repeat(pad);
        }

        try {
            return Base64.getDecoder().decode(std);
        } catch (IllegalArgumentException e) {
            LOGGER.warning("decodeBase64Url: invalid base64 content (len=" + 
                (original==null?0:original.length()) + ") snippet='" + 
                (original.length()>60?original.substring(0,60):original) + "'");
            return null;
        }
    }

    private static Long extractEpochTime(String policyJson) {
        if (policyJson == null) return null;
        
        // Cherche "AWS:EpochTime": 1234567890
        Pattern p = Pattern.compile("\\\"AWS:EpochTime\\\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(policyJson);
        if (m.find()) {
            try {
                return Long.parseLong(m.group(1));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    public static final class Result {
        public boolean isAuthenticated;
        public Boolean keyPairIdMatch; // null = indéterminé
        public boolean signatureValid;
        public boolean expired;
        public Long expirationEpoch;
        public String rawPolicy;
        public String error; // message d'erreur agrégé
        public String warning;

        @Override
        public String toString() {
            return "Result{" +
                    "isAuthenticated=" + isAuthenticated +
                    ", keyPairIdMatch=" + keyPairIdMatch +
                    ", signatureValid=" + signatureValid +
                    ", expired=" + expired +
                    ", expirationEpoch=" + expirationEpoch +
                    ", error='" + error + '\'' +
                    ", warning='" + warning + '\'' +
                    '}';
        }
    }
}
