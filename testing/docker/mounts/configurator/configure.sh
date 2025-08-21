#!/bin/sh

set -e

printf "=== ENV VAR VALUES ===\n"
printf "KEYCLOAK_VERSION=%s\n" "$KEYCLOAK_VERSION"
printf "=======================\n"

# Install runtime tools required by the configurator container.
# We use apk (Alpine) to install curl and a JDK.
# apk add --no-cache curl openjdk21


# Wait for Keycloak to become ready.
# For Keycloak >=25 some images expose health on port 9000. Older images use 80.
# We try a primary URL then fall back to a secondary URL to be compatible.
check_keycloak_health() {
  # Accepts a list of URLs to try, in order.
  for url in "$@"; do
    if curl -s --fail "$url" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

# Select primary/secondary health endpoints based on KEYCLOAK_VERSION.
if echo "${KEYCLOAK_VERSION:-}" | grep -E '^(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40)\.' >/dev/null 2>&1; then
  PRIMARY_HEALTH="http://kc-cloudfront-auth_keycloak:9000/health/ready"
  SECONDARY_HEALTH="http://kc-cloudfront-auth_keycloak:80/health/ready"
else
  PRIMARY_HEALTH="http://kc-cloudfront-auth_keycloak:80/health/ready"
  SECONDARY_HEALTH="http://kc-cloudfront-auth_keycloak:9000/health/ready"
fi

while ! check_keycloak_health "$PRIMARY_HEALTH" "$SECONDARY_HEALTH"; do
  printf "Waiting for Keycloak...\n"
  sleep 5
done


# Apply realm configuration using keycloak-config-cli.
printf "Applying realm configuration with keycloak-config-cli\n"

# Map KEYCLOAK_VERSION -> a compatible keycloak-config-cli release.
# This mapping is conservative and keeps existing choices intact.
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
    # Default: use the newest known mapping.
    KC_CONFIG_CLI_KC_VERSION="26.1.0"
    KC_CONFIG_CLI_VERSION="6.4.0"
    printf "Unrecognized KEYCLOAK_VERSION='%s', defaulting keycloak-config-cli to KC %s\n" \
      "$KEYCLOAK_VERSION" "$KC_CONFIG_CLI_KC_VERSION"
    ;;
esac

KC_CONFIG_CLI_JAR="keycloak-config-cli-${KC_CONFIG_CLI_KC_VERSION}.jar"
KC_CONFIG_CLI_URL="https://github.com/adorsys/keycloak-config-cli/releases/download/v${KC_CONFIG_CLI_VERSION}/${KC_CONFIG_CLI_JAR}"


# Download keycloak-config-cli if not already present in /tmp.
if [ ! -f "/tmp/${KC_CONFIG_CLI_JAR}" ]; then
  printf "Downloading keycloak-config-cli v%s (for Keycloak %s)...\n" \
    "$KC_CONFIG_CLI_VERSION" "$KC_CONFIG_CLI_KC_VERSION"
  curl -L -o "/tmp/${KC_CONFIG_CLI_JAR}" "$KC_CONFIG_CLI_URL"
else
  printf "keycloak-config-cli v%s already present, skipping download\n" "$KC_CONFIG_CLI_VERSION"
fi


# Run the configurator JAR to import the realm configuration.
printf "Running keycloak-config-cli to import realm configuration\n"
java -jar "/tmp/${KC_CONFIG_CLI_JAR}" \
  --keycloak.url=http://kc-cloudfront-auth_keycloak:80 \
  --keycloak.ssl-verify=false \
  --keycloak.user=${KCA_KC_ADMIN_USER} \
  --keycloak.password=${KCA_KC_ADMIN_PASSWORD} \
  --import.files.locations=/mnt/docker/realm-config.json \
  --import.var-substitution.enabled=true

printf "Realm configuration applied successfully\n"