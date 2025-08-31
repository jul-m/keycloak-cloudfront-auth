# Démo : Keycloak + CloudFront Auth Simulator

Cette démo permet d'explorer rapidement l'extension `keycloak-cloudfront-auth` avec Docker, sans rien déployer sur AWS.
Elle combine une instance Keycloak préconfigurée avec un simulateur CloudFront local afin de reproduire le flux complet d'authentification (requête protégée → 403 interne → redirection vers Keycloak → callback → génération de cookies CloudFront signés).
Le simulateur propose une page de diagnostic sur l'authentification, et la possibilité de définir une application web à afficher en cas d'authentification réussie.

Le fichier `docker/demo/compose.yml` lance un environnement de démonstration minimal :
- un conteneur Keycloak préconfiguré avec l'extension `keycloak-cloudfront-auth` ;
- un conteneur "CloudFront Auth Simulator" (basé sur OpenResty, un serveur web basé sur Nginx et Lua) qui simule le comportement de CloudFront, propose une page de diagnostic et peut afficher une application web en cas d'authentification réussie.

Cette page explique comment démarrer rapidement la démo, les rôles des deux conteneurs, les variables d'environnement disponibles et des conseils de dépannage.


## Prérequis
- Docker et Docker Compose (version supportant la syntaxe `docker compose -f - up`).
- Si vous avez cloné le dépôt localement, le script `./run.sh` à la racine peut lancer la stack.


## Démarrage rapide
1) Lancer directement depuis l'URL GitHub (pas besoin de cloner) :

```bash
curl -fsSL https://raw.githubusercontent.com/jul-m/keycloak-cloudfront-auth/refs/heads/main/docker/demo/compose.yml | docker compose -f - up -d
```

2) Si vous avez cloné le dépôt en local, vous pouvez utiliser le script `./run.sh` à la racine du projet :

```bash
./run.sh docker-run demo        # mode foreground (logs visibles)
./run.sh docker-run demo -d     # mode détaché (background)
./run.sh docker-run help        # afficher l'aide et les options
```

Ports par défaut et noms de conteneurs
- `kca-demo_keycloak` (service `keycloak`) : port hôte 8080 -> conteneur port 80, URL: http://localhost:8080/
- `kca-demo_cf-auth-sim` (service `cf-auth-sim`) : port hôte 8081 -> conteneur port 80, URL: http://localhost:8081/

3) Utilisation / scénario de test (configuration par défaut)
- Ouvrir la page du simulateur : `http://localhost:8081`. Comme vous n'êtes pas authentifié, vous serez redirigé vers Keycloak pour vous connecter.
- S'authentifier avec les identifiants de l'utilisateur par défaut : username `user1` / password `password123`.
- Si l'authentification réussit, le simulateur affiche une page de diagnostic avec l'état de l'authentification, le contenu des cookies signés et le détail des vérifications effectuées.


## Rôles des containers
- **keycloak** : instance Keycloak (image `ghcr.io/jul-m/keycloak-cloudfront-auth-demo`) contenant l'extension `keycloak-cloudfront-auth`. Fournit la console d'administration, le realm de démonstration et l'endpoint `/cloudfront-auth/` utilisé par CloudFront.
- **cf-auth-sim** : simulateur CloudFront avec page de diagnostic. Il joue le rôle de CloudFront afin de tester localement le flux complet (redir. 403 → Keycloak → callback → génération de cookies CloudFront signés). Il propose également une page de diagnostic pour visualiser les cookies générés et les informations de session (conditions d'affichage configurables via la variable `KCA_DEBUG_PAGE_NO_AUTH`). Il est possible de définir l'URL d'une application web à présenter après authentification réussie (variable `KCA_APP_URL`).


## Variables d'environnement et options utiles
Le fichier `compose.yml` accepte des variables d'environnement pour personnaliser l'environnement de démonstration.

- Si vous utilisez directement Compose, définissez les valeurs en tant que variables d'environnement avant d'exécuter la commande `docker compose` :
  ```bash
  # Changer les ports par défaut:
  export KCA_KC_HOST_PORT=9000
  export KCA_OPENRESTY_HOST_PORT=9001
  curl -fsSL https://raw.githubusercontent.com/jul-m/keycloak-cloudfront-auth/refs/heads/main/docker/demo/compose.yml | docker compose -f - up -d
  ```
- Si vous utilisez le script `./run.sh`, celui-ci accepte l'option `--vars` pour définir les variables d'environnement :
  ```bash
  ./run.sh docker-run demo --vars KCA_KC_HOST_PORT=9000 KCA_OPENRESTY_HOST_PORT=9001 -d
  ```

\
**Liste des variables disponibles (valeurs par défaut indiquées entre parenthèses) :**

Paramétrage du simulateur CloudFront :
- `KCA_OPENRESTY_HOST_PORT` (`8081`) : Port hôte exposé pour le conteneur simulateur CloudFront.
- `KCA_APP_URL`: URL de l'application à afficher en cas d'authentification réussie (mode reverse-proxy). Si non définie, une page de diagnostic est affichée.
- `KCA_DEBUG_PAGE_NO_AUTH` (`on_error`) : Condition d'affichage de la page debug du simulateur (`always`, `never` ou `on_error`) :
  - `always`: Affiche la page debug même si l'utilisateur n'est pas authentifié.
  - `on_error`: Affiche la page debug uniquement en présence de cookies signés invalides (par défaut).
  - `never`: N'affiche jamais la page debug (équivalent au comportement réel de CloudFront: redirigera de nouveau vers Keycloak).
  -  Note : si `KCA_APP_URL` n'est pas définie, la page debug est toujours affichée en cas d'authentification réussie.
- `KCA_KC_REALM_NAME` (`cloudfront-auth-demo`) : Nom du Realm Keycloak utilisé pour l'authentification.
- `KCA_KC_CLIENT_ID` (`cloudfront-demo-client`) : ID du client à utiliser pour l'authentification.
- `KCA_KC_CLIENT_SECRET` (`ClientSecret123`) : Secret du client utilisé pour l'authentification.
- `KCA_CF_SIGN_KEY_ID` (`ABCDEFGH`) : ID de la clé publique CloudFront.
- `KCA_CF_AUTH_SIM_VERSION` (`latest`) : Tag de l'image Docker pour l'instance du simulateur CloudFront.

Paramétrage de Keycloak :
- `KCA_KC_HOST_PORT` (`8080`) : Port hôte exposé pour le conteneur Keycloak.
- `KCA_KC_ADMIN_USER` (`admin`) et `KCA_KC_ADMIN_PASSWORD` (`admin`) : Identifiants bootstrap admin Keycloak.
- `KCA_KC_DEMO_VERSION` (`latest`) : Tag de l'image Docker pour l'instance Keycloak de démo.

Paramétrage de l'extension `keycloak-cloudfront-auth` (détails dans [Configuration Globale](../../README.md#configuration-globale)) :
- `KCA_KC_AUTH_REDIRECT_DELAY` (`1`) : Délai JS avant redirection vers l'authentification (dans la page de redirection). Variable `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_DELAY`.
- `KCA_KC_AUTH_REDIRECT_FALLBACK_DELAY` (`2`) : Délai avec redirection meta-refresh de secours. Variable `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_FALLBACK_DELAY`.
- `KCA_KC_AUTH_ACCESS_ROLES` (`cloudfront-access`) : Nom de rôles client requis pour accéder à la ressource protégée. Variable `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_ACCESS_ROLES`.
- `KCA_KC_AUTH_AUTH_COOKIES_ATTRIBUTES` (`Path=/; HttpOnly`) : Attributs des cookies signés. Variable `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_AUTH_COOKIES_ATTRIBUTES`.
- `KCA_KC_AUTH_DISPLAY_REQUEST_ID` (`true`) : afficher l'ID de requête CloudFront dans les pages d'erreur. Variable `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_DISPLAY_REQUEST_ID`.


## Versions
- Par défaut, le fichier `compose.yml` utilise les images `latest` pour les conteneurs Keycloak et le simulateur CloudFront.
- Vous pouvez spécifier une version particulière en définissant les variables `KCA_KC_DEMO_VERSION` et `KCA_CF_AUTH_SIM_VERSION`.
- Keycloak : 
  - Pour les images Keycloak de demo, il existe généralement une image par version principale de Keycloak pour chaque version supportée de l'extension `keycloak-cloudfront-auth`.
  - Les tags des images sont au format `KC<KC_VERSION>-<EXT_VERSION>` (exemple : `KC26.3-1.0.0`).
  - Pour chaque version de Keycloak, un tag `KC<KC_VERSION>-latest` pointe vers la dernière version de l'extension supportée pour cette version de Keycloak.
  - Enfin, le tag `latest` pointe vers la dernière version stable de l'extension pour la version la plus récente de Keycloak supportée.
  - Liste des images disponibles : https://ghcr.io/jul-m/keycloak-cloudfront-auth-demo
- Simulateur :
  - Le simulateur CloudFront dispose de son propre cycle de versions, décrit dans un fichier [CHANGELOG](../cf-auth-sim/CHANGELOG.md).
  - Le tag `latest` pointe vers la dernière version stable publiée.
  - Liste des images disponibles : https://ghcr.io/jul-m/keycloak-cloudfront-auth-simulator