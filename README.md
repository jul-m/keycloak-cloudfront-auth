# Keycloak CloudFront Authentication Extension

Cette extension Keycloak fournit une authentification pour AWS CloudFront en remplacement d'une solution basée sur Lambda.

## Prérequis

- Keycloak 26.0.7 ou supérieur
- Java 17 ou supérieur
- Maven 3.8 ou supérieur

## Installation

1. Compiler l'extension :
```bash
mvn clean package
```

2. Copier le fichier JAR généré dans le dossier `providers` de Keycloak :
```bash
cp target/keycloak-cloudfront-auth-1.0.0-SNAPSHOT.jar /path/to/keycloak/providers/
```

3. Configurer la clé privée CloudFront :
   - Définir la variable d'environnement `CLOUDFRONT_PRIVATE_KEY` avec la clé privée au format PEM

## Configuration CloudFront

1. Récupérer la clé publique du Realm Keycloak :
   - Accéder à l'interface d'administration Keycloak
   - Sélectionner le Realm souhaité
   - Aller dans "Realm Settings" > "Keys"
   - Copier la clé publique RS256 (format PEM)

2. Configurer la clé publique dans CloudFront :
   - Aller dans la console AWS CloudFront
   - Dans "Public keys", créer une nouvelle clé publique
   - Coller la clé publique RS256 du Realm
   - Noter l'ID de la clé publique qui sera utilisé dans la configuration

3. Configurer la distribution CloudFront :
   - Ajouter une origine Keycloak :
     - Domaine : URL de votre serveur Keycloak
     - Protocole : HTTPS uniquement
     - Port : 443 (par défaut)
   
   - Créer un comportement pour `/.cdn-auth/*` :
     - Origine : Serveur Keycloak
     - Viewer Protocol Policy : Redirect HTTP to HTTPS
     - Cache Policy : CachingDisabled
     - Origin Request Policy : AllViewer
     - Response Headers Policy : CORS-With-Preflight
   
   - Pour chaque chemin à protéger, configurer :
     - Trusted Key Groups : Ajouter le groupe de clés créé
     - Viewer Protocol Policy : Redirect HTTP to HTTPS
     - Cache Policy : Selon vos besoins
     - Origin Request Policy : AllViewer
     - Response Headers Policy : Selon vos besoins
     - Custom Error Response pour 403 :
       - Error Caching Minimum TTL : 0
       - Response Page Path : `/.cdn-auth/_cf_redirect_403`
       - HTTP Response Code : 200
     - Headers d'origine :
       - `kc-realm-name` : Nom du realm Keycloak
       - `kc-client-id` : ID du client Keycloak
       - `kc-client-secret` : Secret du client Keycloak
       - `cf-sign-key-id` : ID de la clé publique CloudFront

## Configuration Keycloak

### conf/keycloak.conf
```ini
spi-realm-restapi-extension-cloudfront-auth-redirect-delay=0
spi-realm-restapi-extension-cloudfront-auth-redirect-failback-delay=5
spi-realm-restapi-extension-cloudfront-auth-display-request-id=true
spi-realm-restapi-extension-cloudfront-auth-access-roles=cloudfront-access,webapp-access
spi-realm-restapi-extension-cloudfront-auth-auth-cookies-attributes=Path=/; HttpOnly
```

### Paramètres en ligne de commande
```ini
--spi-realm-restapi-extension-cloudfront-auth-redirect-delay=0
--spi-realm-restapi-extension-cloudfront-auth-redirect-failback-delay=5
--spi-realm-restapi-extension-cloudfront-auth-display-request-id=true
--spi-realm-restapi-extension-cloudfront-auth-access-roles=cloudfront-access,webapp-access
--spi-realm-restapi-extension-cloudfront-auth-auth-cookies-attributes="Path=/; HttpOnly"
```

### Format des variables d'environnement
```ini
KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_DELAY=0
KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_FAILBACK_DELAY=5
KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_DISPLAY_REQUEST_ID=true
KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_ACCESS_ROLES=cloudfront-access,webapp-access
KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_AUTH_COOKIES_ATTRIBUTES="Path=/; HttpOnly"
```


## Fonctionnement

1. Lorsqu'un utilisateur non authentifié tente d'accéder à une ressource protégée :
   - CloudFront le redirige vers `/.cdn-auth/_cf_redirect_403`
   - L'extension génère une page de redirection vers l'authentification Keycloak

2. Après authentification réussie :
   - L'utilisateur est redirigé vers `/.cdn-auth/callback`
   - L'extension vérifie l'authentification et les droits
   - Si autorisé, l'extension génère des cookies signés CloudFront
   - L'utilisateur est redirigé vers l'URL d'origine avec les cookies signés

## Sécurité

- L'extension vérifie le secret du client Keycloak
- Les cookies sont générés avec le flag Secure et HttpOnly
- La clé privée CloudFront est stockée de manière sécurisée dans une variable d'environnement
