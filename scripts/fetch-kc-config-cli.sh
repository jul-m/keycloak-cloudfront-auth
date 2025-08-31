#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <KC_VERSION>
Downloads the matching keycloak-config-cli jar into lib/keycloak-config-cli/
If the target file already exists, nothing is downloaded.

Example: $0 26.3
EOF
  exit 2
}

if [ "$#" -ne 1 ]; then
  usage
fi

KC_VERSION="$1"

if ! [[ "$KC_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
  echo "Warning: KC_VERSION '$KC_VERSION' does not match expected format XX.Y; proceeding with default mapping." >&2
fi

# Map Keycloak version -> keycloak-config-cli versions (copied from build-docker.sh)
case "$KC_VERSION" in
    "26.3")
        KC_CONFIG_CLI_KC_VERSION="26.1.0"
        KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
    "26.2")
        KC_CONFIG_CLI_KC_VERSION="26.1.0"
        KC_CONFIG_CLI_VERSION="6.4.0"
    ;;
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
        KC_CONFIG_CLI_KC_VERSION="26.1.0"
        KC_CONFIG_CLI_VERSION="6.4.0"
        echo "Unrecognized KC_VERSION='$KC_VERSION', defaulting keycloak-config-cli to KC $KC_CONFIG_CLI_KC_VERSION" >&2
    ;;
esac

KC_CONFIG_CLI_RELEASE="v${KC_CONFIG_CLI_VERSION}/keycloak-config-cli-${KC_CONFIG_CLI_KC_VERSION}.jar"

DEST_DIR="lib/keycloak-config-cli"
mkdir -p "$DEST_DIR"
DEST_FILE="$DEST_DIR/keycloak-config-cli-KC${KC_VERSION}.jar"

if [ -f "$DEST_FILE" ]; then
  echo "File already exists: $DEST_FILE -> skipping download"
  exit 0
fi

DOWNLOAD_URL="https://github.com/adorsys/keycloak-config-cli/releases/download/${KC_CONFIG_CLI_RELEASE}"

echo "Downloading keycloak-config-cli from ${DOWNLOAD_URL} -> ${DEST_FILE}"
if command -v curl >/dev/null 2>&1; then
  curl -fSL --retry 3 -o "$DEST_FILE" "$DOWNLOAD_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$DEST_FILE" "$DOWNLOAD_URL"
else
  echo "Neither curl nor wget found; cannot download." >&2
  exit 1
fi

echo "Downloaded to $DEST_FILE"
