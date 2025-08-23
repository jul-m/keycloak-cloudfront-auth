## But court — instructions pour un agent de codage

Écrire en français, code en anglais. Ce fichier résume l'essentiel pour être productif sur ce dépôt.

1) Big picture (flow)
- CloudFront redirige les 403 vers /.cdn-auth/_cf_redirect_403.
- `CloudFrontAuthResource` (JAX-RS) rend une page FreeMarker qui redirige vers Keycloak.
- Après login Keycloak, `/.cdn-auth/callback` valide le code, crée un AccessToken et appelle `CloudFrontCookieSigner.generateSignedCookies` pour émettre les cookies CloudFront signés.

2) Fichiers clés à lire (rapide)
- `src/main/java/fr/julm/keycloak/providers/auth/cloudfront/CloudFrontAuthResource.java` — endpoints, gestion du flux OAuth2, détection de boucle (cookie `cloudfront_auth_loop`).
- `src/main/java/fr/julm/keycloak/providers/auth/cloudfront/CloudFrontCookieSigner.java` — génération des cookies signés, cache des clés via ConcurrentHashMap, utilise `session.keys()` pour récupérer la clé active RS256.
- `src/main/java/fr/julm/keycloak/providers/auth/cloudfront/*ProviderFactory.java` — enregistrement SPI.
- `src/main/resources/html/*.ftl` — templates utilisateur (redirect.ftl, error.ftl).
- `src/main/resources/META-INF/services/*` et `target/classes/META-INF/services/*` — enregistrement des services SPI.

3) Commandes de build & dev utiles
- Compiler jar: `mvn clean package` (ou `./build.sh` qui gère versions Keycloak et suffixes).
- Artefact: `target/keycloak-cloudfront-auth-*KC<version>*.jar` (le script `build.sh` recherche ce motif).
- Intégration rapide: `cd docker/dev-tests && docker-compose up` (installe automatiquement le provider depuis mounts/configurator/providers).
- Tests d'intégration: `./test-integration.sh` (présent dans la racine / scripts selon usage).

4) Conventions runtime & sécurité
- La clé privée CloudFront doit rester hors logs: variable d'environnement `CLOUDFRONT_PRIVATE_KEY` (PEM).
- SPI options: `spi-realm-restapi-extension-cloudfront-auth-*` ou variables `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_*`.
- En-têtes obligatoires envoyés par CloudFront vers Keycloak: `kc-realm-name`, `kc-client-id`, `kc-client-secret`, `kc-cf-sign-key-id` (nom observé dans le code).

5) Patterns et pièges spécifiques
- Les factories SPI sont détectées via `META-INF/services` — modifier/ajouter les fichiers correspondants pour que Keycloak charge la SPI.
- Les FreeMarker `.ftl` sont la surface UI; évitez de modifier la logique d'URL dans `CloudFrontAuthResource` sans mettre à jour les templates.
- `CloudFrontCookieSigner` met les clés de signature en cache par `RealmModel` — si vous changez la façon dont les clés sont gérées, ajoutez invalidation/rotation.
- Le script `scripts/build.sh` supporte des builds multi-versions Keycloak (voir liste KEYCLOAK_VERSIONS dans le script).

6) Intégration CloudFront (rappels concrets)
- Créer un behavior pour `/.cdn-auth/*` (no-cache) et un Custom Error Response 403 -> `/.cdn-auth/_cf_redirect_403` (HTTP 200 rendu).
- CloudFront public key RS256 doit correspondre à la clé publique du Realm Keycloak; l'ID de clé publique est fourni via `kc-cf-sign-key-id`.

7) Debug rapide
- Activer logs pour `fr.julm.keycloak.providers.auth.cloudfront` (voir `src/main/resources/logging.properties`).
- Option SPI `display-request-id` active l'affichage de l'ID de requête dans la page d'erreur (utile pour corréler les logs).

Si un point manque (par ex. format exact d'une variable d'environnement non trouvée dans le repo), indiquez-le et j'itérerai la fiche.
