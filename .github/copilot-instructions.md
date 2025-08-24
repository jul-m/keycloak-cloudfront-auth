## But court — instructions pour un agent de codage

Écrire en français, code en anglais. Ce fichier résume l'essentiel pour être productif sur ce dépôt.

1) Big picture (architecture & flow)
- Extension Keycloak SPI qui génère des cookies CloudFront signés pour protéger distributions AWS.
- CloudFront redirige les 403 vers `/.cdn-auth/_cf_redirect_403` (Custom Error Response).
- `CloudFrontAuthResource` (JAX-RS) expose `/cloudfront-auth/.cdn-auth/*` et rend pages FreeMarker.
- Flux OAuth2 : redirect → auth Keycloak → callback → génération cookies signés → accès autorisé.
- Headers requis de CloudFront: `kc-realm-name`, `kc-client-id`, `kc-client-secret`, `kc-cf-sign-key-id`.

2) Structure du projet & fichiers critiques
- **Code principal**: `src/main/java/.../cloudfront/` — 9 classes Java (Resource, Signer, Config, Factories)
- **SPI registration**: `src/main/resources/META-INF/services/` — OBLIGATOIRE pour chargement Keycloak
- **Templates UI**: `src/main/resources/html/*.ftl` — redirect.ftl (avec JS), error.ftl
- **Tests intégration**: `src/it/java/.../it/` — tests avec containers Docker complets
- **Environnements Docker**: `docker/{demo,dev-tests,cf-auth-sim}/` — stacks prêtes à l'emploi
- **Scripts automation**: `scripts/{build,test-integration,docker-*}.sh` — outils de build multi-versions

3) Workflows de développement essentiels
- **Setup rapide**: `./run.sh docker-run dev-tests` — lance stack complète depuis `docker/dev-tests/compose.yml`
- **Build multi-versions**: `./run.sh build [25.0|26.0|26.1|26.2|26.3]` — compile JAR spécifique à version KC
- **Build + test**: `./run.sh build 26.3 -t --keep-containers=on-failure` — avec tests d'intégration complets
- **Build + run**: `./run.sh build 26.3 -r` — compile puis lance automatiquement environnement dev
- **Démo publique**: `./run.sh docker-run demo` — environnement démonstration avec simulateur CloudFront
- **Artefacts**: `dist/keycloak-cloudfront-auth-*KC<version>*.jar` après build réussi

4) Configuration & intégration Keycloak
- **SPI Provider ID**: "cloudfront-auth" (dans CloudFrontAuthResourceProviderFactory)
- **Path exposé**: `/cloudfront-auth/.cdn-auth/*` (configuré dans @Path de CloudFrontAuthResource)
- **Config globale**: variables `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_*`
- **Paramètres SPI**: `redirect-delay`, `redirect-fallback-delay`, `display-request-id`, `access-roles`, `auth-cookies-attributes`
- **Cache clés RSA**: par RealmModel dans `CloudFrontCookieSigner.signingKeysCache` (session.keys() → Algorithm.RS256)

5) Environnements Docker & tests
- **`docker/dev-tests/`**: stack développement avec auto-configuration (configure-start.sh + keycloak-config-cli)
- **`docker/demo/`**: environnement démonstration public, realm pré-configuré (demo-realm-config.json)
- **`docker/cf-auth-sim/`**: simulateur CloudFront (OpenResty/Nginx + scripts Lua) pour tests sans AWS
- **Tests d'intégration**: `src/it/` — CloudFrontAuthExtensionIT, KeycloakInstanceIT, outils simulation CF
- **CI/CD**: `.github/workflows/integration-tests.yml` — pipeline automatisé multi-versions

6) Templates & patterns UI
- **FreeMarker**: `src/main/resources/html/{redirect,error}.ftl` avec variables `${authUrl}`, `${redirectUriPath}`, `${redirectFallbackDelay}`
- **JavaScript dynamique**: redirect.ftl construit `redirect_uri` avec `original_uri` parameter automatiquement
- **Messages i18n**: `src/main/resources/messages/messages_en.properties` pour labels interface
- **Loop detection**: cookie `cloudfront_auth_loop`, seuil 10 tentatives/60sec, gestion dans CloudFrontAuthResource

7) Debug & troubleshooting
- **Logs**: activer `fr.julm.keycloak.providers.auth.cloudfront` level DEBUG
- **Request tracing**: `display-request-id=true` → affiche X-Amz-Cf-Id dans pages erreur
- **Environnement local**: `docker/dev-tests` ou `docker/demo` pour tests complets sans dépendance AWS
- **Configuration**: vérifier `src/it/resources/logging.properties` pour config logs des tests
