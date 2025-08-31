# Common configuration for Keycloak proxy locations
proxy_set_header kc-realm-name $ENV_KC_REALM_NAME;
proxy_set_header kc-client-id $ENV_KC_CLIENT_ID;
proxy_set_header kc-client-secret $ENV_KC_CLIENT_SECRET;
proxy_set_header kc-cf-sign-key-id $ENV_KC_CF_SIGN_KEY_ID;

proxy_method GET;
proxy_set_header Host $kc_host;
proxy_pass $ENV_KC_INTERNAL_URL;

# Route Keycloak failures to a Lua error page generator.
error_page 502 503 504 @keycloak_error;
