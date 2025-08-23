#!/bin/sh

set -e

echo "=== ENV VAR VALUES ==="
echo "KEYCLOAK_VERSION=$KCA_KC_VERSION"
echo "KCA_IMPORT_JSON_NAME=$KCA_IMPORT_JSON_NAME"
echo "======================="

DIST_DIR="/mnt/dist"

matches=( "$DIST_DIR"/keycloak-cloudfront-auth-*-KC${KCA_KC_VERSION}*.jar )

if [ "${#matches[@]}" -eq 0 ]; then
  echo "No provider JAR found in $DIST_DIR matching Keycloak $KCA_KC_VERSION" >&2
  echo "Searched pattern: keycloak-cloudfront-auth-*-KC${KCA_KC_VERSION}*.jar" >&2
  echo "Files in $DIST_DIR:" >&2
  ls -1 "$DIST_DIR" || true
  exit 1
fi
if [ "${#matches[@]}" -gt 1 ]; then
  echo "Multiple matching JARs found in $DIST_DIR; using the first one:" >&2
  for f in "${matches[@]}"; do printf '  %s\n' "$f"; done
fi

PROVIDER_JAR_PATH="${matches[0]}"

echo "Copying provider JAR $PROVIDER_JAR_PATH to /opt/keycloak/providers/..."
cp "$PROVIDER_JAR_PATH" "/opt/keycloak/providers/"

echo "Starting Keycloak in development mode..."
/opt/keycloak/bin/kc.sh start-dev --health-enabled=true & \
    KC_PID=$! && \
    # wait for the server TCP port to be open (give up after ~30s)
    for i in $(seq 1 30); do \
        echo "Waiting for Keycloak to start... [$i/30]." && \
    # send a minimal HTTP request on the Keycloak port and verify status 200
    if bash -c \
			'exec 3<>/dev/tcp/127.0.0.1/9000 >/dev/null 2>&1 && \
			printf "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3 \
			&& IFS=$'"'"'\r\n'"'"' read -r status <&3 \
			&& printf "%s" "$status" | grep -qE "HTTP/[0-9.]+[[:space:]]+200"' > /dev/null 2>&1; \
		then break; fi; \
        sleep 2; \
    done && \
    java -jar "/mnt/keycloak-config-cli/keycloak-config-cli.jar" \
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