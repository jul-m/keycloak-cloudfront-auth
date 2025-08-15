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
while ! curl -s http://kc-cloudfront-auth_keycloak:9000/health/ready; do
  echo "Attente de Keycloak..."
  sleep 5
done

# Redémarrage uniquement si des JARs ont été copiés
if [ -n "$(ls -A /mnt/keycloak-providers/)" ]; then
  echo "Redémarrage de Keycloak pour prise en compte des providers"
  docker restart kc-cloudfront-auth_keycloak
  
  while ! curl -s http://kc-cloudfront-auth_keycloak:9000/health/ready; do
    echo "Attente du redémarrage de Keycloak..."
    sleep 5
  done
fi


java --version