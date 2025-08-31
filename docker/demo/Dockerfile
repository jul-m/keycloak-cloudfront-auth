ARG KC_VERSION=latest

FROM quay.io/keycloak/keycloak:${KC_VERSION} AS builder

ARG PROVIDER_JAR_NAME
ARG KC_VERSION

ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

WORKDIR /opt/keycloak
ADD --chown=keycloak:keycloak --chmod=644 dist/${PROVIDER_JAR_NAME} /opt/keycloak/providers/
ADD --chown=keycloak:keycloak --chmod=644 lib/keycloak-config-cli/keycloak-config-cli-KC${KC_VERSION}.jar /tmp/keycloak-config-cli.jar
ADD docker/demo/demo-realm-config.json /tmp/demo-realm-config.json

RUN /opt/keycloak/bin/kc.sh build

RUN /opt/keycloak/bin/kc.sh start-dev --health-enabled=true & \
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
    java -jar "/tmp/keycloak-config-cli.jar" \
        --keycloak.url=http://127.0.0.1:8080 \
        --keycloak.ssl-verify=false \
        --keycloak.user=${KEYCLOAK_ADMIN} \
        --keycloak.password=${KEYCLOAK_ADMIN_PASSWORD} \
        --import.files.locations=/tmp/demo-realm-config.json && \
    echo "Keycloak configuration imported successfully, wait db sync." && \
    sleep 10


FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]