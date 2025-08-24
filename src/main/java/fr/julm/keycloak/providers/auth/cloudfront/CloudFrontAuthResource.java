package fr.julm.keycloak.providers.auth.cloudfront;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import org.jboss.logging.Logger;
import org.keycloak.events.*;
import org.keycloak.models.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser.ParseResult;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.DefaultClientSessionContext;

import fr.julm.keycloak.providers.auth.cloudfront.CloudFrontAuthConfigMapper.CloudFrontAuthClientConfig;


@Path("/cloudfront-auth/.cdn-auth")
public class CloudFrontAuthResource {
    private static final Logger logger = Logger.getLogger(CloudFrontAuthResource.class);
    private static final String LOOP_COOKIE_NAME = "cloudfront_auth_loop";
    private static final int LOOP_COOKIE_MAX_AGE_SEC = 60; // 1 minute
    private static final int LOOP_COOKIE_FAIL_THRESHOLD = 10;

    private final KeycloakSession session;
    private final TokenManager tokenManager;
    private final CloudFrontTemplate redirectTemplate;
    private final CloudFrontTemplate errorTemplate;

    public CloudFrontAuthResource(KeycloakSession session) {
        this.session = session;
        this.tokenManager = new TokenManager();
        this.redirectTemplate = new CloudFrontTemplate("redirect.ftl");
        this.errorTemplate = new CloudFrontTemplate("error.ftl");
    }
    
    @GET
    @Path("/_cf_redirect_403")
    public Response handleRedirect403(
        @HeaderParam("kc-realm-name") String realmName,
        @HeaderParam("kc-client-id") String clientId,
        @HeaderParam("kc-client-secret") @DefaultValue("") String clientSecret,
        @HeaderParam("kc-cf-sign-key-id") String cfSignKeyId,
        @HeaderParam("X-Amz-Cf-Id") String cfRequestId
    ) {
        RealmModel masterRealm = session.realms().getRealmByName("master");
        String requestId = getUuid(cfRequestId);

        // event: Only for errors
        EventBuilder event = new EventBuilder(masterRealm, session)
                                    .event(EventType.LOGIN)
                                    .ipAddress(session.getContext().getConnection().getRemoteAddr())
                                    .detail("request_type", "cloudfront_auth_redirect")
                                    .detail("cloudfront_request_id", cfRequestId);
        
        String logPrefix = "- " + requestId + " - /cloudfront-auth/.cdn-auth/_cf_redirect_403";
        logger.debugf("%s - call handleRedirect403(" +
            "realmName: %s, clientId: %s, clientSecret (Defined: %b), cfSignKeyId: %s, cfRequestId: %s)",
            logPrefix, realmName, clientId, clientSecret.isEmpty(), cfSignKeyId, cfRequestId);

        try {
            // ...existing code...

            if (realmName == null || clientId == null || clientSecret.isEmpty() || cfSignKeyId == null) {
                String errorMessage = String.format("Missing required headers: " +
                        "kc-realm-name: %s, kc-client-id: %s, kc-client-secret (Defined: %b), kc-cf-sign-key-id: %s",
                    realmName, clientId, !clientSecret.isEmpty(), cfSignKeyId);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                session.getContext().setRealm(masterRealm);
                return errorResponse(
                    session, Messages.INVALID_REQUEST, Response.Status.BAD_REQUEST, requestId, event, errorMessage);
            }

            // Authenticate client
            CloudFrontAuthenticateClient authenticatedClient = new CloudFrontAuthenticateClient(
                session, realmName, clientId, clientSecret, logPrefix);

            // TODO: Check if valid signed cookie exists, and return "App 403 error if true"

            event = new EventBuilder(authenticatedClient.realm, session)
                            .event(EventType.LOGIN)
                            .ipAddress(session.getContext().getConnection().getRemoteAddr())
                            .detail("request_type", "cloudfront_auth_redirect")
                            .detail("cloudfront_request_id", cfRequestId)
                            .client(authenticatedClient.client);

            // Build authorization URL
            String authUrl = UriBuilder.fromUri(authenticatedClient.authEndpoint)
                                       .queryParam("client_id", clientId)
                                       .queryParam("response_type", "code")
                                       .queryParam("redirect_uri", authenticatedClient.redirectUri)
                                       .queryParam("scope", "openid")
                                       .toTemplate();

            // Prepare template attributes
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("redirectUriPath", CloudFrontAuthProviderConfig.REDIRECT_URI_PATH);
            attributes.put("authUrl", authUrl);
            attributes.put("redirectDelay", CloudFrontAuthProviderConfig.getRedirectToAuthDelaySec());
            attributes.put(
                "redirectFallbackDelay",
                CloudFrontAuthProviderConfig.getRedirectToAuthFallbackDelaySec());
            
            return redirectTemplate.serve(session, attributes, Response.Status.OK);
        }
        catch (WebApplicationException e) {
            Response response = e.getResponse();
            String message = response.getEntity() == null ? "Unexpected error" : (String) response.getEntity();
            return errorResponse(session, message, response.getStatus(), requestId, event, message);
        }
        catch (Exception e) {
            logger.errorf(e, "%s - Failed to handle redirect", logPrefix);
            return errorResponse(
                session, Messages.INVALID_REQUEST, Response.Status.BAD_REQUEST, requestId, event, e.getMessage());
        }
    }


    @GET
    @Path("/callback")
    public Response handleCallback(
        @HeaderParam("kc-realm-name") String realmName,
        @HeaderParam("kc-client-id") String clientId,
        @HeaderParam("kc-client-secret") @DefaultValue("") String clientSecret,
        @HeaderParam("kc-cf-sign-key-id") String cfSignKeyId,
        @HeaderParam("x-amz-cf-id") String cfRequestId,
        @QueryParam("code") String code,
        @QueryParam("original_uri") String originalUri
    ) {
        String errorMessage;
        RealmModel masterRealm = session.realms().getRealmByName("master");
        EventBuilder event = new EventBuilder(masterRealm, session);
        String requestId = getUuid(cfRequestId);
        String logPrefix = "- " + requestId + " - /cloudfront-auth/.cdn-auth/_cf_callback";
        logger.debugf("%s - call handleCallback(realmName: %s, clientId: %s, clientSecret (Defined: %b), "+
            "cfSignKeyId: %s, cfRequestId: %s, code: %s, originalUri: %s)",
            logPrefix, realmName, clientId, clientSecret.isEmpty(), cfSignKeyId, cfRequestId, code, originalUri);
        
        try {
            if (realmName == null || clientId == null || clientSecret.isEmpty() || cfSignKeyId == null || code == null) {
                errorMessage = String.format("Missing required headers or URL query parameters. " +
                        "Headers: kc-realm-name: %s, kc-client-id: %s, kc-client-secret (Defined: %b), " +
                        "kc-cf-sign-key-id: %s. Query parameters: code: %s, originalUri: %s",
                    realmName, clientId, !clientSecret.isEmpty(), cfSignKeyId, code, originalUri);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                session.getContext().setRealm(masterRealm);
                return errorResponse(
                    session, Messages.INVALID_REQUEST, Response.Status.BAD_REQUEST, requestId, event, errorMessage);
            }

            // Authenticate client
            CloudFrontAuthenticateClient authenticatedClient = new CloudFrontAuthenticateClient(
                session, realmName, clientId, clientSecret, logPrefix);

            // Create event
            event = new EventBuilder(
                    authenticatedClient.realm, session, session.getContext().getConnection()
                ).event(EventType.CODE_TO_TOKEN)
                 .client(authenticatedClient.client)
                 .ipAddress(session.getContext().getConnection().getRemoteAddr())
                 .detail(Details.AUTH_TYPE, "cloudfront")
                 .detail(Details.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE)
                 .detail(Details.CLIENT_AUTH_METHOD, OAuth2Constants.CLIENT_SECRET)
                 .detail("cloudfront_sign_key_id", cfSignKeyId)
                 .detail("cloudfront_request_id", cfRequestId);

            // Parse the code and get the authentication session
            ParseResult parseResult = OAuth2CodeParser.parseCode(session, code, authenticatedClient.realm, event);
            if (parseResult.isIllegalCode()) {
                errorMessage = String.format("Invalid code: %s", code);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                return errorResponse(
                    session, Messages.INVALID_ACCESS_CODE, Response.Status.UNAUTHORIZED, requestId, event, errorMessage);
            }
            if (parseResult.isExpiredCode()) {
                errorMessage = String.format("Expired code: %s", code);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                return errorResponse(
                    session, Messages.EXPIRED_CODE, Response.Status.UNAUTHORIZED, requestId, event, errorMessage);
            }

            AuthenticatedClientSessionModel clientSession = parseResult.getClientSession();
            UserModel user = clientSession.getUserSession().getUser();
            event.user(user).detail(Details.USERNAME, user.getUsername());

            ClientSessionContext sessionContext = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
                clientSession, OAuth2Constants.SCOPE_OPENID, session);

            AccessToken accessToken = this.tokenManager.createClientAccessToken(
                session, authenticatedClient.realm, authenticatedClient.client,
                user, clientSession.getUserSession(), sessionContext);

            // Verify user has required role
            Map<String, Access> resourceAccess = accessToken.getResourceAccess();

            if (!resourceAccess.containsKey(clientId)) {
                errorMessage = String.format(
                    "User '%s' does not have any role in client '%s'", user.getUsername(), clientId);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                return errorResponse(
                    session, Messages.ACCESS_DENIED, Response.Status.UNAUTHORIZED, requestId, event, errorMessage);
            }

            // TODO: if no accessRoles in provider config, no filtering
            if (Collections.disjoint(
                    CloudFrontAuthProviderConfig.getAccessRoles(),
                    resourceAccess.get(clientId).getRoles()
            )) {
                errorMessage = String.format(
                    "User '%s' does not have required role in client '%s'", user.getUsername(), clientId);
                logger.errorf("%s - %s", logPrefix, errorMessage);
                return errorResponse(
                    session, Messages.ACCESS_DENIED, Response.Status.UNAUTHORIZED, requestId, event, errorMessage);
            }

            // TODO: check allowed_origins

            if (originalUri == null) {
                if (authenticatedClient.homeUrl == null) {
                    errorMessage = String.format("No redirect URI found in request and client %s", clientId);
                    logger.errorf("%s - %s", logPrefix, errorMessage);
                    return errorResponse(
                        session, Messages.INVALID_REDIRECT_URI, Response.Status.BAD_REQUEST,
                        requestId, event, errorMessage);
                }
                originalUri = authenticatedClient.homeUrl;
            }

            Instant cookieExpiration = Instant.ofEpochSecond(accessToken.getExp());
            URI originalUriObj = URI.create(originalUri);
            String cookieResourceUrl = originalUriObj.getScheme() + "://" + originalUriObj.getHost() + "/*";

            // Generate signed cookies for CloudFront
            String[] cookies = CloudFrontCookieSigner.generateSignedCookies(
                    session, cfSignKeyId, cookieResourceUrl, cookieExpiration);

            CloudFrontAuthClientConfig cloudfrontClientConfig = new CloudFrontAuthClientConfig(clientSession);

            // Build response with cookies
            Response.ResponseBuilder builder;

            // Loop detection cookie handling: read from request cookie header, increment and attach to response
            String cookieHeader = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.COOKIE);
            int loopCount = 0;
            if (cookieHeader != null) {
                for (String part : cookieHeader.split(";")) {
                    String[] kv = part.trim().split("=", 2);
                    if (kv.length == 2 && kv[0].equals(LOOP_COOKIE_NAME)) {
                        try {
                            loopCount = Integer.parseInt(kv[1]);
                        }
                        catch (NumberFormatException nfe) {
                            loopCount = 0;
                        }
                    }
                }
            }

            loopCount = loopCount + 1;

            String loopCookieHeader = String.format("%s=%d; Max-Age=%d; Path=/; Secure; HttpOnly",
            LOOP_COOKIE_NAME, loopCount, LOOP_COOKIE_MAX_AGE_SEC);

            if (loopCount >= LOOP_COOKIE_FAIL_THRESHOLD) {
                logger.warnf("%s - Loop detection triggered in callback (count=%d)", logPrefix, loopCount);

                Map<String, Object> attributes = new HashMap<>();
                attributes.put("message",
                    "Unable to redirect to the application (error 310). " +
                    "Please contact the administrator if the problem persists."
                );
                if (CloudFrontAuthProviderConfig.displayRequestIdEnabled()) {
                    attributes.put("cfRequestId", requestId);
                }

                // Use centralized errorResponse to render the error page and allow attaching custom headers
                Map<String, String> extraHeaders = Collections.singletonMap(HttpHeaders.SET_COOKIE, loopCookieHeader);
                return buildErrorResponse(session,
                    "Unable to redirect to the application (error 310). "+
                    "Please contact the administrator if the problem persists.",
                    310,
                    requestId,
                    extraHeaders
                );
            }

            builder = Response.status(Response.Status.FOUND)
                               .header(HttpHeaders.LOCATION, originalUri)
                               .cacheControl(CloudFrontTemplate.CACHE_CONTROL_NO_CACHE);

            for (String cookie : cookies) {
                builder.header(HttpHeaders.SET_COOKIE, cookie);
            }

            if (cloudfrontClientConfig.isJwtCookieEnabled()) { // JWT Access Token Cookie
                String encodedAccessToken = session.tokens().encode(accessToken);
                builder.header(HttpHeaders.SET_COOKIE, cloudfrontClientConfig.generateJwtCookie(encodedAccessToken));
            }

            // Attach incremented loop cookie so admin can see the count in case of client-side issues
            builder.header(HttpHeaders.SET_COOKIE, loopCookieHeader);
            event.detail(Details.REDIRECT_URI, originalUri)
                .detail("cookie_expiration", ZonedDateTime.ofInstant(cookieExpiration, ZoneOffset.UTC).toString())
                .detail("cookie_allowed_resources", cookieResourceUrl)
                .detail("jwt_cookie_config", cloudfrontClientConfig.showJwtCookieConfig())
                .success();

            return builder.build();
        }
        catch (WebApplicationException e) {
            Response response = e.getResponse();
            String message = response.getEntity() == null ? "Unexpected error" : (String) response.getEntity();
            return errorResponse(session, message, response.getStatus(), requestId, event, message);
        }
        catch (Exception e) {
            logger.errorf(e, "%s - Error processing token response", logPrefix);
            return errorResponse(
                session, Messages.INVALID_REQUEST, Response.Status.BAD_REQUEST, requestId, event, e.getMessage());
        }
    }

    @OPTIONS
    @Path("{path:.*}")
    public Response handleCorsOptions(@Context HttpHeaders headers) {
        return Response.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                    .header("Access-Control-Max-Age", "86400")
                    .build();
    }

    private Response buildErrorResponse(
        KeycloakSession session, String message, int statusCode, String cfRequestId, Map<String, String> extraHeaders
    ) {
        try {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("message", message);

            if (CloudFrontAuthProviderConfig.displayRequestIdEnabled())
                attributes.put("cfRequestId", cfRequestId);

            String html = this.errorTemplate.render(session, attributes);

            Response.ResponseBuilder builder = Response.status(statusCode)
                                                    .type(MediaType.TEXT_HTML_TYPE)
                                                    .entity(html)
                                                    .cacheControl(CloudFrontTemplate.CACHE_CONTROL_NO_CACHE);

            if (extraHeaders != null) {
                for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                    builder.header(e.getKey(), e.getValue());
                }
            }

            return builder.build();
        }
        catch (Exception e) {
            logger.error("Failed to generate error page", e);
            return CloudFrontTemplate.basicInternalServerErrorPage();
        }
    }

    private Response errorResponse(KeycloakSession session, String message, int statusCode, String cfRequestId) {
        return buildErrorResponse(session, message, statusCode, cfRequestId, null);
    }

    private Response errorResponse(
        KeycloakSession session, String message, Integer statusCode, String cfRequestId,
        EventBuilder event, String eventMessage
    ) {
        if (event.getEvent().getType() == EventType.LOGIN) {
            event.event(EventType.LOGIN_ERROR);
        }
        else {
            event.event(EventType.CODE_TO_TOKEN_ERROR);
        }
        event.detail("response_message", message)
            .detail("response_code", statusCode.toString())
            .error(eventMessage);

        return errorResponse(session, message, statusCode, cfRequestId);
    }

    private Response errorResponse(
        KeycloakSession session, String message, Response.Status status, String cfRequestId,
        EventBuilder event, String eventMessage
    ) {
        return errorResponse(session, message, status.getStatusCode(), cfRequestId, event, eventMessage);
    }

    private static String getUuid(String cfRequestId) {
        if (cfRequestId == null) {
            return UUID.randomUUID().toString();
        }
        return cfRequestId;
    }
}