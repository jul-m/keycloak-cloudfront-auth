# Demo: Keycloak + CloudFront Auth Simulator

[Version Française - French Version](README.FR.md)

This demo lets you quickly explore the `keycloak-cloudfront-auth` extension with Docker, without deploying anything on AWS.
It combines a preconfigured Keycloak instance with a local CloudFront simulator to reproduce the full authentication flow (protected request → internal 403 → redirect to Keycloak → callback → generation of signed CloudFront cookies).
The simulator provides a diagnostic page about authentication and can proxy an application when authentication succeeds.

The file `docker/demo/compose.yml` starts a minimal demo environment:
- a Keycloak container preconfigured with the `keycloak-cloudfront-auth` extension;
- a "CloudFront Auth Simulator" container (based on OpenResty, an Nginx+Lua web server) that simulates CloudFront behavior, offers a diagnostic page, and can display a web app upon successful authentication.

This page explains how to quickly start the demo, the roles of the two containers, available environment variables, and troubleshooting tips.


## Prerequisites
- Docker and Docker Compose (supporting `docker compose -f - up`).
- If you cloned the repo, the root script `./run.sh` can launch the stack.


## Quick start
1) Run directly from GitHub (no clone needed):

```bash
curl -fsSL https://raw.githubusercontent.com/jul-m/keycloak-cloudfront-auth/refs/heads/main/docker/demo/compose.yml | docker compose -f - up -d
```

2) If you cloned locally, you can use the root `./run.sh` script:

```bash
./run.sh docker-run demo        # foreground (streams logs)
./run.sh docker-run demo -d     # detached
./run.sh docker-run help        # help and options
```

Default ports and container names
- `kca-demo_keycloak` (service `keycloak`): host 8080 -> container 80, URL: http://localhost:8080/
- `kca-demo_cf-auth-sim` (service `cf-auth-sim`): host 8081 -> container 80, URL: http://localhost:8081/

3) Usage / test scenario (default configuration)
- Open the simulator page: `http://localhost:8081`. Since you're not authenticated, you'll be redirected to Keycloak to log in.
- Login with the default user: username `user1` / password `password123`.
- If authentication succeeds, the simulator shows a diagnostic page with auth status, signed cookies content, and validation details.


## Container roles
- **keycloak**: Keycloak instance (image `ghcr.io/jul-m/keycloak-cloudfront-auth-demo`) containing the `keycloak-cloudfront-auth` extension. Provides the admin console, the demo realm, and the `/cloudfront-auth/` endpoint used by CloudFront.
- **cf-auth-sim**: CloudFront simulator with a diagnostic page. It plays the role of CloudFront to test the full flow locally (403 → Keycloak → callback → signed CloudFront cookies). It also shows session details (display conditions controlled with `KCA_DEBUG_PAGE_NO_AUTH`). You can set an app URL to present after successful authentication (`KCA_APP_URL`).


## Environment variables and useful options
The `compose.yml` file accepts environment variables to customize the demo.

- If using Compose directly, export variables before running `docker compose`:
  ```bash
  # Change default ports:
  export KCA_KC_HOST_PORT=9000
  export KCA_OPENRESTY_HOST_PORT=9001
  curl -fsSL https://raw.githubusercontent.com/jul-m/keycloak-cloudfront-auth/refs/heads/main/docker/demo/compose.yml | docker compose -f - up -d
  ```
- If using `./run.sh`, it supports `--vars` to define environment variables:
  ```bash
  ./run.sh docker-run demo --vars KCA_KC_HOST_PORT=9000 KCA_OPENRESTY_HOST_PORT=9001 -d
  ```

\
**Available variables (defaults in parentheses):**

CloudFront simulator configuration:
- `KCA_OPENRESTY_HOST_PORT` (`8081`): Host port exposed for the simulator container.
- `KCA_APP_URL`: App URL to display after successful auth (reverse proxy mode). If unset, a diagnostic page is shown.
- `KCA_DEBUG_PAGE_NO_AUTH` (`on_error`): Diagnostic page display condition (`always`, `never`, `on_error`):
  - `always`: Show the page even if not authenticated.
  - `on_error`: Show the page only when invalid signed cookies are present (default).
  - `never`: Never show the page (same as real CloudFront: will redirect again to Keycloak).
  - Note: if `KCA_APP_URL` is not set, the page is always shown after successful authentication.
- `KCA_KC_REALM_NAME` (`cloudfront-auth-demo`): Keycloak realm name used for authentication.
- `KCA_KC_CLIENT_ID` (`cloudfront-demo-client`): Client ID used for authentication.
- `KCA_KC_CLIENT_SECRET` (`ClientSecret123`): Client secret.
- `KCA_CF_SIGN_KEY_ID` (`ABCDEFGH`): CloudFront public key ID.
- `KCA_CF_AUTH_SIM_VERSION` (`latest`): Docker image tag for the CloudFront simulator.

Keycloak configuration:
- `KCA_KC_HOST_PORT` (`8080`): Host port exposed for the Keycloak container.
- `KCA_KC_ADMIN_USER` (`admin`) and `KCA_KC_ADMIN_PASSWORD` (`admin`): Keycloak admin bootstrap credentials.
- `KCA_KC_DEMO_VERSION` (`latest`): Docker image tag for the Keycloak demo instance.

`keycloak-cloudfront-auth` extension configuration (details in [Global Configuration](../../README.md#global-configuration)):
- `KCA_KC_AUTH_REDIRECT_DELAY` (`1`): JS delay before redirect on the redirection page. Env var `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_DELAY`.
- `KCA_KC_AUTH_REDIRECT_FALLBACK_DELAY` (`2`): Fallback meta-refresh delay. Env var `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_REDIRECT_FALLBACK_DELAY`.
- `KCA_KC_AUTH_ACCESS_ROLES` (`cloudfront-access`): Client role names required to access protected resources. Env var `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_ACCESS_ROLES`.
- `KCA_KC_AUTH_AUTH_COOKIES_ATTRIBUTES` (`Path=/; HttpOnly`): Signed cookie attributes. Env var `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_AUTH_COOKIES_ATTRIBUTES`.
- `KCA_KC_AUTH_DISPLAY_REQUEST_ID` (`true`): display CloudFront request ID in error pages. Env var `KC_SPI_REALM_RESTAPI_EXTENSION_CLOUDFRONT_AUTH_DISPLAY_REQUEST_ID`.


## Versions
- By default, `compose.yml` uses `latest` images for both Keycloak and the CloudFront simulator.
- You can pin versions via `KCA_KC_DEMO_VERSION` and `KCA_CF_AUTH_SIM_VERSION`.
- Keycloak:
  - Demo images usually exist per Keycloak major version for each supported extension version.
  - Image tags follow `KC<KC_VERSION>-<EXT_VERSION>` (e.g., `KC26.3-1.0.0`).
  - For each Keycloak version, a `KC<KC_VERSION>-latest` tag points to the latest supported extension for that Keycloak version.
  - The `latest` tag points to the latest stable extension for the most recent supported Keycloak.
  - Available images: https://ghcr.io/jul-m/keycloak-cloudfront-auth-demo
- Simulator:
  - The simulator has its own release cycle, see [CHANGELOG](../cf-auth-sim/CHANGELOG.md).
  - The `latest` tag points to the latest stable release.
  - Available images: https://ghcr.io/jul-m/keycloak-cloudfront-auth-simulator