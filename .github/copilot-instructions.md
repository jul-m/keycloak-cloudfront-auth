# Keycloak CloudFront Authentication Extension - Copilot Instructions

## Architecture Overview

This Keycloak extension replaces AWS Lambda@Edge with a server-side solution for CloudFront authentication. The authentication flow:

1. **Unauthorized access attempt** → CloudFront redirects to `/.cdn-auth/_cf_redirect_403`
2. **Auth redirect** → Extension generates HTML redirect page to Keycloak OpenID
3. **Post-authentication** → Callback to `/.cdn-auth/callback` generates signed CloudFront cookies
4. **Authorized access** → User redirected with valid CloudFront cookies

## Key Components

### Keycloak Providers (SPI)
- `CloudFrontAuthResourceProviderFactory`: Main entry point (ID: `cloudfront-auth`)
- `CloudFrontAuthResource`: REST endpoints (`/.cdn-auth/*`)
- `CloudFrontCookieSigner`: Generates signed cookies with CloudFront private key
- `CloudFrontAuthConfigMapper`: Protocol mapper for client configuration

### Runtime Configuration
Configuration via `conf/keycloak.conf` with namespace `spi-realm-restapi-extension-cloudfront-auth-*`:
```properties
spi-realm-restapi-extension-cloudfront-auth-redirect-delay=0
spi-realm-restapi-extension-cloudfront-auth-access-roles=cloudfront-access,webapp-access
```

## Development Patterns

### Build & Packaging
```bash
mvn clean package  # Generates keycloak-cloudfront-auth-0.1.0-KC26-SNAPSHOT.jar
```
JAR deployed to `/opt/keycloak/providers/` with dynamic versioning based on `keycloak.major-version`

### Docker Testing
```bash
cd testing/docker && docker-compose up
```
- Keycloak on port 8080 with extension auto-installed
- `keycloak-providers` volume for hot-reload during development
- `configurator/scripts/configure.sh` script for automatic setup

### Security Model
- **Required CloudFront headers**: `kc-realm-name`, `kc-client-id`, `kc-client-secret`, `cf-sign-key-id`
- **CloudFront private key**: Environment variable `CLOUDFRONT_PRIVATE_KEY` (PEM format)
- **Token validation**: Via Keycloak `TokenManager` with configured role verification

## Codebase Conventions

### Service Structure
- **Factory Pattern**: All providers implement `*ProviderFactory` for SPI injection
- **FreeMarker Templates**: `src/main/resources/html/*.ftl` for redirect/error pages
- **Key Caching**: `ConcurrentHashMap` in `CloudFrontCookieSigner` for performance

### Error Handling
- FreeMarker templates for user display (`error.ftl`, `redirect.ftl`)
- JBoss Logger with configurable level per `fr.julm` package
- Optional request ID for debugging (`display-request-id` config)

### Extension Points
- New endpoints: Extend `CloudFrontAuthResource` with JAX-RS annotations
- Configuration: Add properties to `CloudFrontAuthProviderConfig`
- Protocol mappers: Implement `org.keycloak.protocol.ProtocolMapper`

## External Integrations

### AWS CloudFront
- Distribution must have configured Keycloak origin
- Behavior `/.cdn-auth/*` → Keycloak origin, cache disabled
- Trusted Key Groups with RS256 public key from Keycloak Realm
- Error page 403 → `/.cdn-auth/_cf_redirect_403`

### Common Debugging
- Verify CloudFront headers in Keycloak logs
- CloudFront private key must be valid PEM format
- Public key match between Realm ↔ CloudFront Key Group
- User roles included in configured `access-roles`
