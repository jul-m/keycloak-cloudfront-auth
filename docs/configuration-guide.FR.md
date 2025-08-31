# Guide de configuration — Keycloak + CloudFront (FR)

## Objectif
Ce guide décrit pas à pas la procédure pour protéger une distribution AWS CloudFront avec l'extension Keycloak « keycloak-cloudfront-auth ». Il couvre :
- La configuration côté Keycloak (client OpenID, rôles, mapper optionnel),
- La configuration côté CloudFront (clé publique, origine Keycloak, comportements, règle d'erreur 403),
- Vérifications et dépannage.

## Prérequis
- Un serveur Keycloak avec l'extension `keycloak-cloudfront-auth` installée et active. Voir [la section Installation du README](../README.FR.md#installation) pour les instructions d'installation.
- Accès administrateur au realm de l'instance Keycloak.
- Accès au compte AWS et permissions complètes sur le service CloudFront.
- Une distribution CloudFront configurée pour votre application web.

## Procédure de configuration
### Configuration Keycloak

1. **Créer le client OpenID :**
- Dans l'administration Keycloak, allez dans votre realm → `Clients` → `Create client`.
- Type : `OpenID Connect`.
- Activez les options `Client authentication` et `Standard Flow`.
- Redirect URIs : ajoutez `https://<CLOUDFRONT_DOMAIN>/.cdn-auth/callback/*` (remplacez `<CLOUDFRONT_DOMAIN>` par le domaine de l'application CloudFront).
- Fortement recommandé : définir une valeur pour `Root URL` et/ou `Home URL` (`Home URL` prioritaire si les deux sont définies). L'URL sera utilisée comme URL de redirection après authentification si la redirection initiale n'a pas pu être réalisée en JavaScript, ou si la valeur `original_uri` n'est pas présente dans l'URL lors du callback.

2. **Ajouter le rôle d'accès :**
- Dans l'onglet `Roles`, créez un rôle client nommé `cloudfront-access` (nom configurable via SPI global — voir section [Configuration globale dans README.md](../README.md#configuration-globale)).
- Assignez ce rôle aux utilisateurs ou groupes autorisés à accéder à l'application protégée. Si vous disposez déjà d'un rôle pour autoriser l'accès (de type client ou realm), vous pouvez ajouter le rôle `cloudfront-access` à ce rôle (rôle composite).

3. **Configurer la durée de validité des cookies :**
- La durée de vie définie dans la politique générée dans le cookie `CloudFront-Policy` correspond à celle de l'access-token définie dans le client OpenID :
  - Par défaut, la valeur est celle définie au niveau du realm (`Realm settings` > `Tokens` > `Access Token Lifespan`).
  - Pour définir une valeur spécifique pour le client, allez dans l'onglet `Advanced` du client et définissez `Access Token Lifespan`.
- Pour les cookies en eux-mêmes, par défaut ils n'ont pas de durée de vie, ils durent donc jusqu'à la fermeture du navigateur. Pour changer ce comportement, vous devez ajouter une valeur `Max-Age` dans la configuration globale des cookies, voir [Configuration globale dans README.md](../README.md#configuration-globale).
- Que les cookies expirent ou uniquement la politique définie dans le cookie `CloudFront-Policy`, le résultat est le même : CloudFront redirigera l'utilisateur vers l'authentification au lieu de servir la ressource demandée. Si la session "SSO" du realm est toujours valide, l'utilisateur sera automatiquement redirigé vers le callback, puis l'application avec de nouveaux cookies sans saisie de ses identifiants.
- <ins>**Avertissements** :</ins>
  - Veillez à ne pas mettre une durée trop courte pour l'access-token, car même si l'utilisateur est réauthentifié automatiquement, cela générera un flux de redirection qui peut être perceptible par les utilisateurs.
  - Pour les applications Web de type "page unique JavaScript" dont les API transitent par la distribution CloudFront, un rechargement de la page sera nécessaire à chaque expiration. Il est donc recommandé d'implémenter une détection de l'expiration du token et de rafraîchir la page automatiquement si nécessaire pour ne pas bloquer les utilisateurs.
  - Pour le moment, il n'y a pas de mécanisme permettant d'implémenter le rafraîchissement en arrière-plan des cookies. Il s'agit toutefois d'une fonctionnalité envisagée pour de futures versions.

4. **(Optionnel) Ajouter un cookie contenant l'access-token JWT :**
- Dans l'onglet `Client scopes`, séléctionner le scope dédié au client (`<client-id>-dedicated`).
- Cliquez sur `Configure a new mapper`, puis sur `CloudFront Auth Client Config`.
- Remplissez les champs :
  - `Name`: Nom du mapper, obligatoire pour Keycloak mais pas d'impact sur l'extension (par exemple `CloudFront Auth Client Config`).
  - `JWT Cookie - Enabled`: Cochez pour activer l'ajout du cookie.
  - `JWT Cookie - Cookie Name`: Nom du cookie à créer (par exemple `Jwt-Access-Token`).
  - `JWT Cookie - Cookie Attributes`: Attributs du cookie (par exemple `Path=/; Secure; HttpOnly`).
- Enregistrez le mapper.
- Vous pouvez personnaliser le contenu de l'acces-token via les mappers de la même manière qu'un client OpenID classique.


### Configuration CloudFront

1. **Importer la clé publique du realm Keycloak**
- Dans la console du realm Keycloak :
  - Allez dans `Realm settings` → `Keys`.
  - Repérez la clé : avec l'algorithme `Algorithm`=`RS256`, `Type`=`RSA`, `Use`=`SIG`. Si plusieurs clés correspondent (ajout manuel), analysez les clés dans l'onglet `Add provider` afin de déterminer celle avec le numéro de priorité le plus élevé.
  - Sur la clé concernée, cliquez sur `Public key` et copiez la valeur.
- Dans la console AWS CloudFront :
  - Allez dans `Public keys` → `Create public key`.
  - Nommez la clé, par exemple `Keycloak-RealmName-Key`.
  - Dans le champ `Key`, collez la clé publique copiée depuis Keycloak, en ajoutant `-----BEGIN PUBLIC KEY-----` en 1re ligne et `-----END PUBLIC KEY-----` en dernière ligne.
  - Enregistrez la clé, puis notez l'`ID` de la clé (sera à renseigner dans la distribution CloudFront).
  - Dans `Key groups`, créez un nouveau groupe de clés (ou utilisez un groupe existant) et ajoutez la clé importée dans le groupe.
- La clé sera utilisable par toutes les distributions CloudFront protégées par ce realm Keycloak.

2. **Ajouter l'origine Keycloak**
- Dans la distribution CloudFront à protéger, onglet `Origins` → `Create origin` :
  - `Origin domain` : Domaine public de l'instance Keycloak.
  - `Origin path` : `/cloudfront-auth` (si un préfixe spécifique est nécessaire pour accéder à votre instance Keycloak, ajoutez-le. Exemple: `/keycloak-test1/cloudfront-auth`).
  - `Add custom header` : Ajoutez les en‑têtes suivants :
   - `kc-realm-name` : nom du realm Keycloak.
   - `kc-client-id` : identifiant du client OpenID créé précédemment.
   - `kc-client-secret` : secret du client (à copier depuis l'onglet `Credentials` du client dans Keycloak).
   - `kc-cf-sign-key-id` : ID de la clé importée dans CloudFront (sera la valeur du cookie `CloudFront-Key-Pair-Id`).
   - Adaptez les autres paramètres si nécessaire, et enregistrez l'origine.

3. **Comportement pour `/.cdn-auth/*`**
- Depuis l'onglet `Behaviors` de la distribution CloudFront, ajoutez un nouveau comportement :
  - `Path pattern` : `/.cdn-auth/*`
  - `Origin and origin groups` : Sélectionnez l'origine Keycloak créée précédemment.
  - `Viewer protocol policy` : `Redirect HTTP to HTTPS` (recommandé).
  - `Allowed HTTP methods` : `GET, HEAD`
  - `Restrict viewer access`: `No` (les utilisateurs non authentifiés seront redirigés vers ce comportement pour s'authentifier).
  - `Cache policy` : `CachingDisabled`
  - Adaptez les autres paramètres si nécessaire, et enregistrez le comportement.

4. **Règle de réponse personnalisée 403**
- Depuis l'onglet `Error pages` de la distribution CloudFront, ajoutez une nouvelle règle :
  - `HTTP error code` : `403: Forbidden`
  - `Error caching minimum TTL`: `0`
  - `Customize error response` : `Yes`
  - `Response page path` : `/.cdn-auth/_cf_redirect_403`
  - `HTTP response code` : `403`

5. **Protéger les comportements de l'application**
- Editez les comportements correspondant aux ressources à protéger :
  - `Restrict viewer access` : `Yes`
  - `Trusted authorization type` : `Trusted key groups (recommended)`
  - `Add key groups` : Ajoutez le groupe de clés créé précédemment.

Attendez quelques minutes après la dernière modification afin que celles-ci soient propagées vers les différentes localisations de CloudFront.


### Tester la configuration
1. Conseil : dans un nouvel onglet, ouvrez les outils de développement du navigateur (généralement via la touche F12), puis ouvrez l'onglet Réseau/Network. Filtrez sur "Doc" ou "HTML". Cochez également la case "Preserve log" si elle existe. Cela vous permettra de voir les différentes pages et redirections lors du test.
2. Ouvrez une URL protégée de votre application.
3. Si la configuration est correcte, à la place de la page normalement accessible à cette adresse, une page avec le message *"Redirect to authentication service..."* devrait s'afficher brièvement, puis vous devriez être redirigé vers la page de connexion Keycloak. Dans les outils de développement, vous devez voir la requête avec une réponse 403 initiale, puis un appel vers l'URL `https://<keycloak.domain>/realms/<realm-name>/protocol/openid-connect/auth?[...]` avec un code HTTP 200.
4. Après avoir saisi les identifiants (ou si vous êtes déjà authentifié), vous devriez être redirigé vers une URL `https://<cloudfront.domain>/.cdn-auth/callback?code=...&state=...` avec un code HTTP 302. Cette page doit définir les 3 cookies CloudFront signés (`CloudFront-Policy`, `CloudFront-Signature` et `CloudFront-Key-Pair-Id`, visibles via les headers `Set-Cookie` dans les outils de développement), puis rediriger vers l'URL d'origine (code 302).
5. La page d'origine doit alors se charger correctement (code 200) et les cookies CloudFront signés doivent être présents dans les requêtes (visible dans le détail de la requête dans les outils de développement, ainsi que dans l'onglet Storage/Cookies).


## Dépannage

En cas de problème, nous vous recommandons de suivre les étapes suivantes :
- Dans l'onglet `General`, section `Details` de votre distribution CloudFront, vérifiez que le champ `Last modified` indique une date/heure. S'il indique `Deploying`, patientez jusqu'à ce qu'une date/heure s'affiche (cela indique que la configuration est bien appliquée sur toutes les régions CloudFront).
- Videz le cache CloudFront : onglet `Invalidations` → `Create invalidation`. Saisissez `/*` afin de purger l'intégralité du cache, puis validez. Attendez que l'invalidation soit terminée (état `Completed`).
- Ouvrez une session de navigation privée (incognito) vierge dans votre navigateur, afin d'éviter les problèmes liés au cache ou des interférences avec d'éventuels cookies ou sessions existantes.
- Ouvrez les outils de développement du navigateur comme expliqué dans la section précédente avant de tester l'accès à une URL protégée.
- Testez de nouveau l'accès à une URL protégée.

Si le problème persiste, après avoir suivi les conseils ci-dessus, le chapitre suivant contient des pistes de dépannage selon les symptômes observés.

- **Erreur lors de la requête initiale :**
  - La page est accessible sans authentification :
    - L'option `Restrict viewer access` n'est pas activée sur le comportement CloudFront de la page concernée. Vérifiez que chaque comportement à protéger dispose de cette option activée, avec le groupe de clés correct. **Voir étape 5** de la section [Configuration CloudFront](#configuration-cloudfront).
  - Une erreur contenant le message `Missing Key-Pair-Id query parameter or cookie value` s'affiche :
    - La *Règle de réponse personnalisée 403* n'est pas ou mal configurée. Vérifiez que celle-ci est bien configurée comme **indiqué à l'étape 4** de la section [Configuration CloudFront](#configuration-cloudfront).
  - Une erreur Keycloak *"Invalid Request"* s'affiche :
    - Vérifiez les logs Keycloak, ils devraient contenir la raison de l'erreur. Si `Request ID: [...]` est affiché en bas de page, l'ID peut être recherché dans les logs pour trouver facilement l'erreur correspondante.
    - L'origine Keycloak est peut-être mal configurée. Vérifiez que celle-ci est bien configurée comme **indiqué à l'étape 2** de la section [Configuration CloudFront](#configuration-cloudfront). Vérifiez également les autres paramètres de l'origine (protocole, ports, etc). Si un préfixe doit être ajouté au chemin d'accès, ajoutez le dans le champ `Origin path`.
    - La *Règle de réponse personnalisée 403* est peut être mal configurée. Vérifier que `Response page path` = `/.cdn-auth/_cf_redirect_403` et `HTTP response code` = `403`.
    - Le client OpenID est peut être mal configuré. Vérifiez que celui-ci est bien configuré comme **indiqué à l'étape 1** de la section [Configuration Keycloak](#configuration-keycloak), et que les headers `kc-realm-name`, `kc-client-id` et `kc-client-secret` sont corrects dans l'origine Keycloak.
  - Une erreur CloudFront "504 Gateway Timeout ERROR" s'affiche :
    - L'instance Keycloak n'est peut être pas accessible depuis CloudFront. Vérifiez que l'instance Keycloak est bien accessible publiquement (ou au minimum par CloudFront et vos utilisateurs), et que les paramètres de l'origine Keycloak sont corrects (protocole, ports, etc).
    - La *Règle de réponse personnalisée 403* est peut être mal configurée. Vérifier que `Response page path` = `/.cdn-auth/_cf_redirect_403`.
    - Le comportement `/.cdn-auth/*` est peut être absent ou mal configuré. Vérifiez que celui-ci est bien configuré comme **indiqué à l'étape 3** de la section [Configuration CloudFront](#configuration-cloudfront).
  - Erreur 404 ou autre ne provenant pas de Keycloak ou de CloudFront :
    -  Le comportement `/.cdn-auth/*` n'utilise peut être pas l'origine Keycloak. Vérifiez que `Origin and origin groups` est défini sur l'origine Keycloak.
    -  L'origine Keycloak ne pointe peut être pas sur Keycloak. Vérifiez que `Origin domain` et `Origin path` sont corrects.
    - La *Règle de réponse personnalisée 403* est peut être mal configurée. Vérifier que `Response page path` = `/.cdn-auth/_cf_redirect_403`.
- **La page *"Redirect to authentication service..."* a fonctionné, mais une erreur survient dans l'URL `https://<keycloak.domain>/realms/<realm-name>/protocol/openid-connect/auth?[...]`** :
  - Il s'agit très probablement d'un problème de configuration du client OpenID dans Keycloak (l'étape actuelle est l'authentification OpenID classique et ne passe pas par l'extension `keycloak-cloudfront-auth`, ni par la distribution CloudFront de l'application à protéger). Vérifiez que le client est bien configuré comme **indiqué à l'étape 1** de la section [Configuration Keycloak](#configuration-keycloak).
  - Certaines erreurs sont affichées dans la page d'erreur. Par exemple: "Invalid redirect_uri" (dans ce cas, vérifiez que `Valid Redirect URIs` contient bien `https://<CLOUDFRONT_DOMAIN>/.cdn-auth/callback/*`).
  - Vous pouvez également consulter les logs Keycloak, ils devraient contenir la raison de l'erreur. Cette partie n'est pas gérée par l'extension, mais par Keycloak lui-même, consultez la documentation officielle de Keycloak pour plus d'informations.
- **Erreur après authentification réussie :**
  - L'erreur Keycloak "310" s'affiche → `Unable to redirect to the application (error 310)` :
    - Cette erreur est générée par l'extension `keycloak-cloudfront-auth` lorsqu'il y a eu 10 redirections vers l'URL de callback en l'espace d'une minute. Cela signifie que les cookies signés sont bien générés par l'extension, mais qu'ils ne sont pas acceptés par CloudFront. CloudFront redirige donc de nouveau vers l'URL d'authentification, la session de l'utilisateur étant encore valide, celui-ci est directement redirigé vers le callback qui redirige vers l'URL d'origine avec de nouveaux cookies signés, et ainsi de suite. L'erreur 310 permet d'éviter une boucle infinie.
    - Vérifiez que la clé publique importée dans CloudFront est bien celle du realm Keycloak utilisé et qu'elle est bien placée dans le bon groupe de clés. Voir **étape 1** de la section [Configuration CloudFront](#configuration-cloudfront).
    - Vérifiez que le comportement CloudFront de l'application protégée référence bien le groupe de clés contenant la clé publique du realm Keycloak. Voir **étape 5** de la section [Configuration CloudFront](#configuration-cloudfront).
    - Vérifiez que l'header `kc-cf-sign-key-id` dans l'origine Keycloak contient bien l'ID de la clé publique importée dans CloudFront. Voir **étape 2** de la section [Configuration CloudFront](#configuration-cloudfront).
  - Erreur "Accès refusé/Access Denied" (401) : l'utilisateur n'a pas le rôle `cloudfront-access` (ou autre nom défini dans le paramètre global `spi-realm-restapi-extension-cloudfront-auth-access-roles`). Voir **étape 2** de la section [Configuration Keycloak](#configuration-keycloak).