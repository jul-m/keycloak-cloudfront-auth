# Guide d'utilisation des tests d'intégration

## 🎯 Objectif

Ce système de tests d'intégration permet de tester automatiquement votre extension Keycloak CloudFront Auth avec différentes versions de Keycloak (23, 24, 25, 26) en conditions quasi-réelles.

## 🚀 Utilisation

### Tests rapides

```bash
# Tester toutes les versions de Keycloak supportées
./test-integration.sh

# Tester une version spécifique
./test-integration.sh 26

# Tester plusieurs versions spécifiques
./test-integration.sh 24 25 26
```

### Tests avec Maven

```bash
# Compiler et préparer
mvn clean package -Dkeycloak-major.version=26

# Exécuter les tests d'intégration
mvn failsafe:integration-test failsafe:verify -Dkeycloak-major.version=26

# Tout en une seule commande
mvn clean verify -Dkeycloak-major.version=26
```

## 📋 Ce qui est testé

- **Chargement de l'extension** : Vérification que l'extension est correctement installée dans Keycloak
- **Endpoints CloudFront** : Test des points d'entrée `/_cf_redirect_403` et `/callback`
- **Gestion d'erreurs** : Tests avec headers invalides, realm inexistant, etc.
- **Compatibilité versions** : Validation avec toutes les versions Keycloak supportées

## 🏗️ Architecture

```
src/it/
├── java/
│   └── fr/julm/keycloak/providers/auth/cloudfront/it/
│       ├── AbstractKeycloakIntegrationTest.java    # Classe de base
│       └── CloudFrontAuthFlowIT.java               # Tests du flux
└── resources/
    ├── docker-compose-test.yml                     # Configuration Docker
    └── testcontainers.properties                   # Configuration TestContainers
```

## 🔧 Configuration automatique

Chaque test créé automatiquement :
- Un royaume Keycloak de test (`cloudfront-test`)
- Un client OAuth (`cloudfront-client`)
- Des rôles (`cloudfront-access`, `webapp-access`)
- Un utilisateur de test (`testuser` / `testpass`)

## 📊 Rapports

Les résultats des tests sont disponibles dans :
- `target/failsafe-reports/` : Rapports détaillés XML/HTML
- Console : Résumé des tests réussis/échoués

## 🚨 Prérequis

- Java 17+
- Maven 3.6+
- Docker et Docker Compose en fonctionnement
- Extension compilée dans le dossier `dist/`

## 💡 Conseils

- Les tests prennent environ 2-3 minutes par version de Keycloak (démarrage de Docker)
- En cas d'échec, vérifiez que Docker fonctionne : `docker info`
- Pour déboguer, regardez les logs Docker : `docker-compose -f src/it/resources/docker-compose-test.yml logs`

## 🔗 GitHub Actions

Les tests s'exécutent automatiquement sur GitHub lors de :
- Push vers `main` ou `develop`
- Pull requests
- Déclenchement manuel

## 🎯 Résultat attendu

```bash
✅ Tests passed for Keycloak 23
✅ Tests passed for Keycloak 24  
✅ Tests passed for Keycloak 25
✅ Tests passed for Keycloak 26

🎉 All tests completed successfully!
```
