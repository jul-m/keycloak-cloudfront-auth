# Configuration guide — Keycloak + CloudFront

[Version Française - French Version](configuration-guide.FR.md)

## Goal
This step-by-step guide explains how to protect an AWS CloudFront distribution using the Keycloak extension "keycloak-cloudfront-auth". It covers:
- Keycloak configuration (OpenID client, roles, optional mapper),
- CloudFront configuration (public key, Keycloak origin, behaviors, 403 error rule),
- Checks and troubleshooting.

## Prerequisites
- A Keycloak server with the `keycloak-cloudfront-auth` extension installed and active. See [Installation in the README](../README.md#installation) for setup instructions.
- Admin access to the realm on your Keycloak instance.
- AWS account access with full permissions for CloudFront.
- A CloudFront distribution configured for your web application.

## Setup procedure
### Keycloak configuration

1. Create the OpenID client
- In the Keycloak admin console, go to your realm → `Clients` → `Create client`.
- Type: `OpenID Connect`.
- Enable `Client authentication` and `Standard Flow`.
- Redirect URIs: add `https://<CLOUDFRONT_DOMAIN>/.cdn-auth/callback/*` (replace `<CLOUDFRONT_DOMAIN>` with your CloudFront distribution domain).
- Strongly recommended: set `Root URL` and/or `Home URL` (`Home URL` takes precedence when both are set). This URL is used as the post-auth redirect target if the initial JavaScript redirect couldn't run, or if `original_uri` is missing on callback.

2. Add the access role
- In the `Roles` tab, create a client role named `cloudfront-access` (name is configurable via global SPI — see [Global configuration in README.md](../README.md#global-configuration)).
- Assign this role to users or groups allowed to access the protected app. If you already have an authorization role (client or realm), you can add `cloudfront-access` as a composite role.

3. Configure cookie lifetime
- The lifetime defined in the policy stored in the `CloudFront-Policy` cookie matches the access token lifespan of the OpenID client:
  - By default, it's the realm-level value (`Realm settings` > `Tokens` > `Access Token Lifespan`).
  - To set a client-specific value, go to the client's `Advanced` tab and set `Access Token Lifespan`.
- Cookies themselves are session cookies by default (last until the browser is closed). To change this, add a `Max-Age` in the global cookie configuration; see [Global configuration in README.md](../README.md#global-configuration).
- Whether cookies expire or only the policy in `CloudFront-Policy` expires, the effect is the same: CloudFront will redirect the user to authentication instead of serving the requested resource. If the realm SSO session is still valid, the user will be redirected automatically through the callback and back to the app with fresh cookies, without re-entering credentials.
- Warnings:
  - Avoid setting a too-short access token lifespan; even with automatic re-auth, users may notice the redirect flow.
  - For JavaScript SPA apps whose APIs go through CloudFront, a page reload is required at each expiration. Implement token-expiration detection and an automatic reload to avoid blocking users.
  - There's currently no background refresh for cookies. This may come in future versions.

4. (Optional) Add a cookie containing the JWT access token
- In `Client scopes`, select the dedicated client scope (`<client-id>-dedicated`).
- Click `Configure a new mapper`, then select `CloudFront Auth Client Config`.
- Fill the fields:
  - `Name`: Mapper name (required by Keycloak, no impact on the extension, e.g., `CloudFront Auth Client Config`).
  - `JWT Cookie - Enabled`: Check to enable cookie creation.
  - `JWT Cookie - Cookie Name`: Cookie name (e.g., `Jwt-Access-Token`).
  - `JWT Cookie - Cookie Attributes`: Cookie attributes (e.g., `Path=/; Secure; HttpOnly`).
- Save the mapper.
- You can customize the access token content with regular OpenID mappers as usual.


### CloudFront configuration

1. Import the Keycloak realm public key
- In the Keycloak realm console:
  - Go to `Realm settings` → `Keys`.
  - Identify the key with `Algorithm`=`RS256`, `Type`=`RSA`, `Use`=`SIG`. If multiple keys match (manually added), inspect the `Add provider` tab to find the one with the highest priority.
  - Click `Public key` on the relevant key and copy the value.
- In the AWS CloudFront console:
  - Go to `Public keys` → `Create public key`.
  - Name it, e.g., `Keycloak-RealmName-Key`.
  - In `Key`, paste the public key copied from Keycloak, adding `-----BEGIN PUBLIC KEY-----` on the first line and `-----END PUBLIC KEY-----` on the last line.
  - Save the key, then note its `ID` (will be referenced in the CloudFront distribution).
  - In `Key groups`, create a new key group (or use an existing one) and add the imported key to the group.
- The key can be used by all CloudFront distributions protected by this Keycloak realm.

2. Add the Keycloak origin
- In the distribution to protect, `Origins` → `Create origin`:
  - `Origin domain`: Public domain of the Keycloak instance.
  - `Origin path`: `/cloudfront-auth` (if your Keycloak is behind a path prefix, include it, e.g., `/keycloak-test1/cloudfront-auth`).
  - `Add custom header`: add the following headers:
    - `kc-realm-name`: Keycloak realm name.
    - `kc-client-id`: OpenID client ID created earlier.
    - `kc-client-secret`: Client secret (copy from the client's `Credentials` tab in Keycloak).
    - `kc-cf-sign-key-id`: ID of the public key imported in CloudFront (will be the `CloudFront-Key-Pair-Id` cookie value).
  - Adjust other settings as needed and save the origin.

3. Behavior for `/.cdn-auth/*`
- From the distribution `Behaviors` tab, add a new behavior:
  - `Path pattern`: `/.cdn-auth/*`
  - `Origin and origin groups`: select the Keycloak origin created above.
  - `Viewer protocol policy`: `Redirect HTTP to HTTPS` (recommended).
  - `Allowed HTTP methods`: `GET, HEAD`
  - `Restrict viewer access`: `No` (unauthenticated users will be redirected here to authenticate).
  - `Cache policy`: `CachingDisabled`
  - Adjust other settings as needed and save.

4. 403 custom error response
- From the `Error pages` tab, add a new rule:
  - `HTTP error code`: `403: Forbidden`
  - `Error caching minimum TTL`: `0`
  - `Customize error response`: `Yes`
  - `Response page path`: `/.cdn-auth/_cf_redirect_403`
  - `HTTP response code`: `403`

5. Protect the application behaviors
- Edit the behaviors corresponding to protected resources:
  - `Restrict viewer access`: `Yes`
  - `Trusted authorization type`: `Trusted key groups (recommended)`
  - `Add key groups`: add the key group created earlier.

Wait a few minutes after the last change for propagation across CloudFront edge locations.


### Test the configuration
1. Tip: open your browser DevTools in a new tab (usually F12), then open the Network panel. Filter on "Doc" or "HTML". Also check "Preserve log" if available. This helps visualize the sequence of pages and redirects.
2. Open a protected URL of your application.
3. If the configuration is correct, instead of the expected page, a page with the message "Redirect to authentication service..." should appear briefly, then you'll be redirected to the Keycloak login page. In DevTools, you should see the initial 403 response, then a request to `https://<keycloak.domain>/realms/<realm-name>/protocol/openid-connect/auth?[...]` with HTTP 200.
4. After logging in (or if you already had a session), you'll be redirected to `https://<cloudfront.domain>/.cdn-auth/callback?code=...&state=...` with HTTP 302. This page sets the 3 signed CloudFront cookies (`CloudFront-Policy`, `CloudFront-Signature`, `CloudFront-Key-Pair-Id` via `Set-Cookie` headers), then redirects to the original URL (302).
5. The original page should then load (200) and the signed CloudFront cookies should be present on requests (visible in the request details and in Storage/Cookies).


## Troubleshooting

If issues arise, follow these steps first:
- In the distribution `General` tab, `Details` section, check `Last modified` shows a date/time. If it shows `Deploying`, wait until a date/time is displayed (indicating the config is fully applied across regions).
- Purge the CloudFront cache: `Invalidations` → `Create invalidation`. Enter `/*` to purge everything, then wait for status `Completed`.
- Open a fresh private/incognito browser session to avoid cache/cookies/session interference.
- Open browser DevTools as described before testing a protected URL.
- Test again.

If problems persist, use the following hints based on observed symptoms.

- Initial request errors:
  - The page is accessible without authentication:
    - `Restrict viewer access` is not enabled on the CloudFront behavior for that page. Ensure each protected behavior has this option enabled with the correct key group. See step 5 in [CloudFront configuration](#cloudfront-configuration).
  - Error message `Missing Key-Pair-Id query parameter or cookie value`:
    - The 403 custom error response is missing or misconfigured. Ensure it matches step 4 in [CloudFront configuration](#cloudfront-configuration).
  - Keycloak "Invalid Request" error page:
    - Check Keycloak logs; the reason should be present. If `Request ID: [...]` is shown, use it to find the corresponding log.
    - The Keycloak origin may be misconfigured. Ensure it matches step 2 in [CloudFront configuration](#cloudfront-configuration). Also verify protocol/ports. If a path prefix is required, include it in `Origin path`.
    - The 403 custom error response may be wrong. Ensure `Response page path` = `/.cdn-auth/_cf_redirect_403` and `HTTP response code` = `403`.
    - The OpenID client may be misconfigured. Ensure step 1 in [Keycloak configuration](#keycloak-configuration) is correct, and headers `kc-realm-name`, `kc-client-id`, `kc-client-secret` are correct on the Keycloak origin.
  - CloudFront "504 Gateway Timeout ERROR":
    - Keycloak might not be reachable from CloudFront. Ensure Keycloak is publicly reachable (or at least by CloudFront and your users), and origin settings are correct (protocol, ports, etc.).
    - The 403 custom error response may be wrong. Ensure `Response page path` = `/.cdn-auth/_cf_redirect_403`.
    - The `/.cdn-auth/*` behavior may be missing or misconfigured. Ensure it matches step 3 in [CloudFront configuration](#cloudfront-configuration).
  - 404 or other error not from Keycloak or CloudFront:
    - The `/.cdn-auth/*` behavior may not target the Keycloak origin. Ensure `Origin and origin groups` is set to the Keycloak origin.
    - The Keycloak origin may not point to Keycloak. Check `Origin domain` and `Origin path`.
    - The 403 custom error response may be wrong. Ensure `Response page path` = `/.cdn-auth/_cf_redirect_403`.
- The page "Redirect to authentication service..." appeared, but an error occurs on `https://<keycloak.domain>/realms/<realm-name>/protocol/openid-connect/auth?[...]`:
  - Most likely an OpenID client configuration issue in Keycloak (this step is standard OIDC, not handled by the extension or CloudFront). Ensure step 1 in [Keycloak configuration](#keycloak-configuration) is correct.
  - Some errors are visible on the page, e.g., "Invalid redirect_uri" (ensure `Valid Redirect URIs` includes `https://<CLOUDFRONT_DOMAIN>/.cdn-auth/callback/*`).
  - Also check Keycloak logs; this part is handled by Keycloak itself. See Keycloak documentation for details.
- Error after successful authentication:
  - Keycloak error "310" → `Unable to redirect to the application (error 310)`:
    - This is thrown by `keycloak-cloudfront-auth` when 10 redirects to the callback occur within a minute. It means the extension generates cookies but CloudFront doesn't accept them, so CloudFront redirects to auth again; since the user still has a valid session, they're redirected back to the callback, new cookies are generated, and so on. Error 310 prevents infinite loops.
    - Ensure the public key imported in CloudFront is the one from the Keycloak realm and is in the correct key group. See step 1 in [CloudFront configuration](#cloudfront-configuration).
    - Ensure the CloudFront behavior of the protected app references the key group containing the realm public key. See step 5 in [CloudFront configuration](#cloudfront-configuration).
    - Ensure the `kc-cf-sign-key-id` header in the Keycloak origin contains the ID of the CloudFront public key. See step 2 in [CloudFront configuration](#cloudfront-configuration).
  - "Access denied" (401): the user lacks the `cloudfront-access` role (or the name defined in the global option `spi-realm-restapi-extension-cloudfront-auth-access-roles`). See step 2 in [Keycloak configuration](#keycloak-configuration).