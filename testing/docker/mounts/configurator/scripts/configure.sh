#!/bin/sh

set -e

echo "=== ENV VAR VALUES ==="
echo "KEYCLOAK_VERSION=$KEYCLOAK_VERSION"
echo "PROVIDER_JAR_URL=$PROVIDER_JAR_URL"
echo "======================="

apk add --no-cache curl openjdk21

# Gestion des providers
if [ ! -z "$PROVIDER_JAR_URL" ]; then
  echo "Téléchargement du JAR depuis $PROVIDER_JAR_URL"
  curl -L -o /mnt/keycloak-providers/cloudfront-auth.jar "$PROVIDER_JAR_URL"
elif [ "$(ls -A /mnt/providers/*.jar 2>/dev/null)" ]; then
  echo "Copie des JARs depuis /mnt/providers"
  cp /mnt/providers/*.jar /mnt/keycloak-providers/
else
  echo "Aucun JAR à installer"
fi

# Attente que Keycloak soit prêt
# Keycloak >=25 expose le health sur le port 9000 par défaut dans certaines images.
# Pour être compatible avec les versions plus anciennes (<=24) on tente d'abord
# le port attendu selon la version puis on fait un fallback sur l'autre port.
check_keycloak_health() {
  # Receives a space-separated list of URLs to try in order
  for url in "$@"; do
    if curl -s --fail "$url" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

if echo "${KEYCLOAK_VERSION:-}" | grep -E '^(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40)\.' >/dev/null 2>&1; then
  PRIMARY_HEALTH="http://kc-cloudfront-auth_keycloak:9000/health/ready"
  SECONDARY_HEALTH="http://kc-cloudfront-auth_keycloak:80/health/ready"
else
  PRIMARY_HEALTH="http://kc-cloudfront-auth_keycloak:80/health/ready"
  SECONDARY_HEALTH="http://kc-cloudfront-auth_keycloak:9000/health/ready"
fi

while ! check_keycloak_health "$PRIMARY_HEALTH" "$SECONDARY_HEALTH"; do
  echo "Attente de Keycloak..."
  sleep 5
done

# Redémarrage uniquement si des JARs ont été copiés
if [ -n "$(ls -A /mnt/keycloak-providers/)" ]; then
  echo "Redémarrage de Keycloak pour prise en compte des providers"
  docker restart kc-cloudfront-auth_keycloak
  
  # Après redémarrage, réutiliser la même logique de checks (primary puis fallback)
  while ! check_keycloak_health "$PRIMARY_HEALTH" "$SECONDARY_HEALTH"; do
    echo "Attente du redémarrage de Keycloak..."
    sleep 5
  done
fi

# Configuration du realm avec keycloak-config-cli
echo "Configuration du realm cloudfront-test avec keycloak-config-cli"

# Détermination de la version keycloak-config-cli en fonction de la version Keycloak
# Format: KEYCLOAK_VERSION (ex: 26.3) -> KC_CONFIG_CLI_KC_VERSION (ex: 26.1.0)
case "$KEYCLOAK_VERSION" in
  "26.1")
    KC_CONFIG_CLI_KC_VERSION="26.1.0"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "26.0")
    KC_CONFIG_CLI_KC_VERSION="26.0.5"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "25.0")
    KC_CONFIG_CLI_KC_VERSION="25.0.1"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "24.0")
    KC_CONFIG_CLI_KC_VERSION="24.0.5"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "23.0")
    KC_CONFIG_CLI_KC_VERSION="23.0.7"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "22.0")
    KC_CONFIG_CLI_KC_VERSION="22.0.4"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "21.1")
    KC_CONFIG_CLI_KC_VERSION="21.1.2"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  "18.0")
    KC_CONFIG_CLI_KC_VERSION="18.0.2"
    KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
  *)
    # Par défaut, utiliser la version la plus récente
    KC_CONFIG_CLI_KC_VERSION="26.1.0"
    KC_CONFIG_CLI_VERSION="6.4.0"
    echo "Version Keycloak $KEYCLOAK_VERSION non reconnue, utilisation de keycloak-config-cli pour KC 26.1.0"
    ;;
esac

KC_CONFIG_CLI_JAR="keycloak-config-cli-${KC_CONFIG_CLI_KC_VERSION}.jar"
KC_CONFIG_CLI_URL="https://github.com/adorsys/keycloak-config-cli/releases/download/v${KC_CONFIG_CLI_VERSION}/${KC_CONFIG_CLI_JAR}"

# Téléchargement de keycloak-config-cli seulement si pas déjà présent
if [ ! -f "/tmp/${KC_CONFIG_CLI_JAR}" ]; then
  echo "Téléchargement de keycloak-config-cli v${KC_CONFIG_CLI_VERSION} (pour Keycloak ${KC_CONFIG_CLI_KC_VERSION})..."
  curl -L -o "/tmp/${KC_CONFIG_CLI_JAR}" "$KC_CONFIG_CLI_URL"
else
  echo "keycloak-config-cli v${KC_CONFIG_CLI_VERSION} déjà présent, pas de retéléchargement"
fi

# Configuration du realm
echo "Application de la configuration du realm..."
java -jar "/tmp/${KC_CONFIG_CLI_JAR}" \
  --keycloak.url=http://kc-cloudfront-auth_keycloak:80 \
  --keycloak.ssl-verify=false \
  --keycloak.user=admin \
  --keycloak.password=admin \
  --import.files.locations=/mnt/config/realm-config.json

echo "Configuration terminée avec succès !"