package fr.julm.keycloak.providers.auth.cloudfront;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;

public class CloudFrontAuthenticateClient {
    private static final Logger logger = Logger.getLogger(CloudFrontAuthenticateClient.class);

    public RealmModel realm;
    public ClientModel client;
    public String authEndpoint;
    public String redirectUri;
    public String rootUrl;
    public String homeUrl;
    public String tokenEndpoint;

    public CloudFrontAuthenticateClient(
        KeycloakSession session, String realmName, String clientId, String clientSecret, String logPrefix
    ) throws WebApplicationException {
        logger.debugf("%s - Authenticating client [realm=%s, client=%s]", logPrefix, realmName, clientId);

        this.realm = session.realms().getRealmByName(realmName);
        if (this.realm == null) {
            logger.errorf("%s - Realm not found [realm=%s]", logPrefix, realmName);
            session.getContext().setRealm(session.realms().getRealmByName("master"));
            throw new WebApplicationException(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity("Realm not found")
                            .build()
            );
        }

        this.client = this.realm.getClientByClientId(clientId);
        if (this.client == null) {
            logger.errorf("%s - Client not found [realm=%s, client=%s]", logPrefix, realmName, clientId);
            throw new WebApplicationException(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity("Client not found")
                            .build()
            );
        }

        if (!client.isEnabled()) {
            logger.errorf("%s - Client is disabled [realm=%s, client=%s]", logPrefix, realmName, clientId);
            throw new WebApplicationException(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity("Client is disabled")
                            .build()
            );
        }

        if (!client.isStandardFlowEnabled()) {
            logger.errorf(
                "%s - Standard flow not enabled [realm=%s, client=%s]", logPrefix, realmName, clientId);
            throw new WebApplicationException(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity("Standard flow not enabled")
                            .build()
            );
        }

        if (!this.client.validateSecret(clientSecret)) {
            logger.errorf(
                "%s - Invalid client credentials [realm=%s, client=%s]", logPrefix, realmName, clientId);
            throw new WebApplicationException(
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity("Invalid client credentials")
                            .build()
            );
        }

        // TODO: Check if client has CloudFront role

        logger.infof("%s - Client authenticated [realm=%s, client=%s]", logPrefix, realmName, clientId);

        this.homeUrl = "undefined";
        if (this.client.getBaseUrl().endsWith("/")) {
            this.rootUrl = this.client.getBaseUrl().substring(0, this.client.getBaseUrl().length() - 1);
        }
        else if (this.rootUrl != null) {
            this.homeUrl = this.client.getBaseUrl();
        }

        this.rootUrl = "undefined";
        if (this.client.getRootUrl().endsWith("/")) {
            this.rootUrl = this.client.getRootUrl().substring(0, this.client.getRootUrl().length() - 1);
        }
        else if (this.client.getRootUrl() != null) {
            this.rootUrl = this.client.getRootUrl();
        }

        if (this.rootUrl == "undefined" && this.homeUrl != "undefined") {
            this.rootUrl = this.homeUrl;
        }
        else if (this.homeUrl == "undefined" && this.rootUrl != "undefined") {
            this.homeUrl = this.rootUrl;
        }

        String realmBaseUrl = String.format(
            "%srealms/%s/protocol/openid-connect", session.getContext().getAuthServerUrl(), realmName
        );

        this.authEndpoint = realmBaseUrl + "/auth";
        this.tokenEndpoint = realmBaseUrl + "/token";
        String redirectUri = UriBuilder.fromUri(this.homeUrl)
            .path(CloudFrontAuthProviderConfig.REDIRECT_URI_PATH)
            .build()
            .toString();
        this.redirectUri = redirectUri;

        session.getContext().setRealm(this.realm);
        session.getContext().setClient(this.client);

        logger.debugf(
            "%s - Client details [authEndpoint=%s, redirectUri=%s, rootUrl=%s, homeUrl=%s, tokenEndpoint=%s]",
            logPrefix, this.authEndpoint, this.redirectUri, this.rootUrl, this.homeUrl, this.tokenEndpoint);
    }
}
