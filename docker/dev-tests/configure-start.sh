#!/bin/sh

set -e

echo "=================================================="
echo "Starting configure-start.sh script..."

# Determine KC_VERSION (format MAJOR.MINOR) from /opt/keycloak/version.txt when not provided.
# Example file content: "Keycloak - Version 26.3.3" -> KC_VERSION=26.3
if [ -z "${KC_VERSION:-}" ]; then
  if [ -r "/opt/keycloak/version.txt" ]; then
    # extract first occurrence of N.N (major.minor)
    kc_ver=$(grep -Eo '[0-9]+\.[0-9]+' /opt/keycloak/version.txt | head -n1 || true)
    if [ -n "$kc_ver" ]; then
      KC_VERSION="$kc_ver"
    else
      echo "Could not parse Keycloak version from /opt/keycloak/version.txt" >&2
    fi
  else
    echo "/opt/keycloak/version.txt not readable; KC_VERSION not set from file" >&2
  fi
fi

DIST_DIR="/mnt/dist"
# If a specific provider JAR name is provided via env and not 'auto', prefer it.
if [ -n "${KCA_PROVIDER_JAR_NAME:-}" ] && [ "${KCA_PROVIDER_JAR_NAME:-}" != "auto" ]; then
  PROVIDER_JAR_PATH="${DIST_DIR}/${KCA_PROVIDER_JAR_NAME}"
  if [ ! -f "$PROVIDER_JAR_PATH" ]; then
    echo "KCA_PROVIDER_JAR_NAME is set to '$KCA_PROVIDER_JAR_NAME' but file does not exist in $DIST_DIR" >&2
    echo "Files in $DIST_DIR:" >&2
    ls -1 "$DIST_DIR" || true
    exit 1
  fi
  echo "Using provider JAR from KCA_PROVIDER_JAR_NAME: $PROVIDER_JAR_PATH"
else
  if [ "${KCA_PROVIDER_JAR_NAME:-}" = "auto" ]; then
    echo "KCA_PROVIDER_JAR_NAME=auto: performing automatic JAR detection in $DIST_DIR"
  fi
  matches=( "$DIST_DIR"/keycloak-cloudfront-auth-*-KC${KC_VERSION}*.jar )

  if [ "${#matches[@]}" -eq 0 ]; then
    echo "No provider JAR found in $DIST_DIR matching Keycloak $KC_VERSION" >&2
    echo "Searched pattern: keycloak-cloudfront-auth-*-KC${KC_VERSION}*.jar" >&2
    echo "Files in $DIST_DIR:" >&2
    ls -1 "$DIST_DIR" || true
    exit 1
  fi
  if [ "${#matches[@]}" -gt 1 ]; then
    echo "Multiple matching JARs found in $DIST_DIR; using the first one:" >&2
    for f in "${matches[@]}"; do printf '  %s\n' "$f"; done
  fi

  PROVIDER_JAR_PATH="${matches[0]}"
fi

echo "=== VAR VALUES ==="
echo "KEYCLOAK_VERSION=$KC_VERSION"
echo "KCA_PROVIDER_JAR_NAME=$KCA_PROVIDER_JAR_NAME"
echo "KCA_PROVIDER_JAR_PATH=$PROVIDER_JAR_PATH"
echo "KCA_IMPORT_JSON_NAME=$KCA_IMPORT_JSON_NAME"
echo "=================================================="

echo "Copying provider JAR $PROVIDER_JAR_PATH to /opt/keycloak/providers/..."
cp "$PROVIDER_JAR_PATH" "/opt/keycloak/providers/"

echo "Starting Keycloak in development mode..."
/opt/keycloak/bin/kc.sh start-dev --health-enabled=true & \
    KC_PID=$! && \
    # wait for the server TCP port to be open (give up after ~30s)
    for i in $(seq 1 30); do \
        echo "Waiting for Keycloak to start... [$i/60]." && \
    # send a minimal HTTP request on the Keycloak port and verify status 200
    if bash -c \
			'exec 3<>/dev/tcp/127.0.0.1/9000 >/dev/null 2>&1 && \
			printf "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3 \
			&& IFS=$'"'"'\r\n'"'"' read -r status <&3 \
			&& printf "%s" "$status" | grep -qE "HTTP/[0-9.]+[[:space:]]+200"' > /dev/null 2>&1; \
		then break; fi; \
        sleep 2; \
    done && \
    java -jar "/mnt/lib/keycloak-config-cli/keycloak-config-cli-KC$KC_VERSION.jar" \
        --keycloak.url=http://127.0.0.1:80 \
        --keycloak.ssl-verify=false \
        --keycloak.user=${KEYCLOAK_ADMIN} \
        --keycloak.password=${KEYCLOAK_ADMIN_PASSWORD} \
        --import.files.locations=/mnt/configs/${KCA_IMPORT_JSON_NAME} \
        --import.var-substitution.enabled=true && \
  echo "Keycloak configuration imported successfully."

# Forward SIGINT/SIGTERM to the Keycloak process for graceful shutdown
trap 'echo "Forwarding signal to Keycloak (pid=${KC_PID})"; kill -TERM "${KC_PID}" 2>/dev/null || true' INT TERM
echo "Keycloak started (pid=${KC_PID})."
wait "${KC_PID}"
exit_code=$?
echo "Keycloak exited with code ${exit_code}"
exit ${exit_code}