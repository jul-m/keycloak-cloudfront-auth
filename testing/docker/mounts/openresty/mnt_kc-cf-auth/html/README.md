# Système de Gestion d'Erreurs Unifié

Ce dossier contient le nouveau système de gestion d'erreurs unifié pour l'extension Keycloak CloudFront Auth.

## 🗂️ Structure des fichiers

### Template principal
- **`50X-tpl.html`** : Template HTML unifié avec variables dynamiques
- **`error_pages.lua`** : Module Lua pour la génération dynamique des pages

### Pages de fallback
- **`502-keycloak-fallback.html`** : Page statique de secours pour erreurs 502
- **`50x.html`** : Page d'erreur générique (maintenue pour compatibilité)
- **`503.html`** : Page d'erreur 503 (maintenue pour compatibilité)

### Fichiers obsolètes (à supprimer)
- **`502-keycloak.html`** : Remplacé par le système unifié

## 🔧 Fonctionnement

### 1. Gestion dynamique via Lua
Le module `error_pages.lua` génère des pages d'erreur personnalisées en fonction du code d'erreur :

```lua
local error_pages = require "error_pages"
error_pages.serve_error_page("502", "Message personnalisé optionnel")
```

### 2. Configuration nginx
La configuration nginx utilise des locations spécialisées :

```nginx
# Erreurs Keycloak spécifiques
location @keycloak_error {
    internal;
    content_by_lua_block {
        local error_pages = require "error_pages"
        local error_code = ngx.var.status or "502"
        error_pages.serve_error_page(error_code, nil)
    }
}

# Erreurs générales
location @general_error {
    internal;
    content_by_lua_block {
        local error_pages = require "error_pages"
        local error_code = ngx.var.status or "500"
        error_pages.serve_error_page(error_code, nil)
    }
}
```

### 3. Types d'erreur supportés

| Code | Titre | Retry Auto | Délai | Contexte |
|------|-------|------------|-------|----------|
| **502** | Service d'Authentification Indisponible | ✅ | 10s | Keycloak down |
| **503** | Service Temporairement Indisponible | ✅ | 30s | Maintenance |
| **504** | Délai d'Attente Dépassé | ✅ | 5s | Timeout |
| **500** | Erreur Interne du Serveur | ❌ | - | Erreur critique |

## 🎨 Personnalisation

### Variables du template
Le template `50X-tpl.html` utilise les variables suivantes :

- **`PAGE_TITLE`** : Titre de la page
- **`ERROR_CODE`** : Code d'erreur (502, 503, etc.)
- **`ERROR_TITLE`** : Titre principal affiché
- **`ERROR_DESCRIPTION`** : Description du problème
- **`AUTO_RETRY`** : Activation du retry automatique (true/false)

### Ajout d'un nouveau type d'erreur

1. Modifier `error_pages.lua` :
```lua
error_configs["404"] = {
    PAGE_TITLE = "Page non trouvée",
    ERROR_CODE = "404",
    ERROR_TITLE = "Page Non Trouvée",
    -- ... autres propriétés
}
```

2. La page sera automatiquement générée lors des erreurs 404.

## 🚀 Avantages

### ✅ Unification
- **Un seul template** pour tous les types d'erreur
- **Cohérence visuelle** garantie
- **Maintenance simplifiée**

### ✅ Flexibilité
- **Configuration par code d'erreur**
- **Messages personnalisables**
- **Retry automatique configurable**

### ✅ Performance
- **Génération à la volée** (pas de fichiers multiples)
- **Cache Lua** pour les templates
- **Fallback statique** en cas de problème

### ✅ Expérience utilisateur
- **Design moderne et responsive**
- **Informations détaillées** sur le problème
- **Actions claires** (retry, retour accueil)
- **Feedback visuel** (animations, compteurs)

## 🔄 Migration

### Étapes pour nettoyer l'ancien système :

1. **Vérifier le bon fonctionnement** du nouveau système
2. **Supprimer les fichiers obsolètes** :
   ```bash
   rm 502-keycloak.html
   ```
3. **Optionnel** : Supprimer `50x.html` et `503.html` si plus utilisés

### Test du système :

1. **Arrêter Keycloak** et tenter une authentification → Page 502 unifiée
2. **Simuler une erreur 500** → Page 500 unifiée  
3. **Vérifier le retry automatique** → Compteur et rechargement

## 📝 Notes techniques

- Les templates utilisent **Mustache-like syntax** avec `{{VARIABLE}}`
- Le module Lua est **chargé automatiquement** par OpenResty
- Les **pages de fallback** sont servies en cas d'erreur Lua
- Le système est **compatible** avec les configurations nginx existantes
