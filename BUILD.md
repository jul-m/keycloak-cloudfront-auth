# Build Multi-Versions Guide

Ce guide explique comment construire des versions de l'extension compatibles avec différentes versions majeures de Keycloak.

## Profils disponibles

- `keycloak-26` (par défaut) : Keycloak 26.0.7
- `keycloak-25` : Keycloak 25.0.6  
- `keycloak-24` : Keycloak 24.0.5
- `keycloak-23` : Keycloak 23.0.7

## Construction d'une version spécifique

### Version par défaut (Keycloak 26)
```bash
mvn clean package
```

### Version spécifique
```bash
# Pour Keycloak 25
mvn clean package -Pkeycloak-25

# Pour Keycloak 24
mvn clean package -Pkeycloak-24

# Pour Keycloak 23
mvn clean package -Pkeycloak-23
```

### Avec une version personnalisée
```bash
mvn clean package -Pkeycloak-25 -Drevision=1.0.0
```

## Construction automatique de toutes les versions

Utilisez le script fourni pour construire automatiquement toutes les versions :

```bash
# Avec la version par défaut (0.1.0)
./build-all-versions.sh

# Avec une version spécifique
./build-all-versions.sh 1.0.0
```

Les artefacts générés seront placés dans le dossier `dist/` :
- `keycloak-cloudfront-auth-1.0.0-KC26-SNAPSHOT.jar`
- `keycloak-cloudfront-auth-1.0.0-KC25-SNAPSHOT.jar`
- `keycloak-cloudfront-auth-1.0.0-KC24-SNAPSHOT.jar`
- `keycloak-cloudfront-auth-1.0.0-KC23-SNAPSHOT.jar`

## Déploiement

Chaque JAR généré est compatible avec sa version correspondante de Keycloak :

1. Copiez le JAR approprié dans `/opt/keycloak/providers/`
2. Redémarrez Keycloak
3. L'extension sera automatiquement chargée

## GitHub Actions (optionnel)

Pour automatiser la construction lors des releases, vous pouvez utiliser le workflow GitHub Actions fourni dans `.github/workflows/build-multi-version.yml`.
