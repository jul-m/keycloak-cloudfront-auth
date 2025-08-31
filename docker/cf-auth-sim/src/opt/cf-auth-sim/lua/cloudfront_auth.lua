local _M = {}
local cjson = require "cjson"
local resty_rsa = require "resty.rsa"
local http = require "resty.http"

-- Environment variables
local ENV_KC_URL = os.getenv("KC_URL")
local ENV_KC_INTERNAL_URL = os.getenv("KC_INTERNAL_URL")
local ENV_KC_REALM_NAME = os.getenv("KC_REALM_NAME")
local ENV_KC_CLIENT_ID = os.getenv("KC_CLIENT_ID")
local ENV_KC_CLIENT_SECRET = os.getenv("KC_CLIENT_SECRET")
local ENV_KC_CF_SIGN_KEY_ID = os.getenv("KC_CF_SIGN_KEY_ID")
local ENV_DEBUG_PAGE_NO_AUTH = os.getenv("DEBUG_PAGE_NO_AUTH")

local config = {
    status = "not_loaded",
    public_key = nil,
    last_key_attempt = 0,
    key_retry_interval = 5 -- retry every 5 seconds on failure
}

local function base64url_decode(str)
    -- Simple base64url -> base64 conversion used for JWK params
    if not str then return nil end
    str = tostring(str)
    str = str:gsub("-", "+"):gsub("_", "/")
    local mod = #str % 4
    if mod ~= 0 then
        str = str .. string.rep("=", 4 - mod)
    end
    return ngx.decode_base64(str)
end


local function extract_json_fragment(s)
    if not s or s == "" then return s end
    -- find first '{' or '['
    local start_idx = s:find("{", 1, true) or s:find("[", 1, true)
    if not start_idx then return s end
    -- find last matching '}' or ']' scanning backwards
    local last_idx = nil
    for i = #s, start_idx, -1 do
        local ch = s:sub(i, i)
        if ch == '}' or ch == ']' then
            last_idx = i
            break
        end
    end
    if not last_idx then return s end
    return s:sub(start_idx, last_idx)
end

local function check_keycloak_connectivity()
    local kc_url = ENV_KC_INTERNAL_URL or ENV_KC_URL
    local realm_name = ENV_KC_REALM_NAME

    if not kc_url then
        return false, "KC_URL / KC_INTERNAL_URL not set"
    end
    if not realm_name then
        return false, "KC_REALM_NAME not set"
    end

    local health_url = kc_url .. "/realms/" .. realm_name
    ngx.log(ngx.INFO, "Checking Keycloak connectivity: ", health_url)

    local httpc = http.new()
    httpc:set_timeout(3000) -- 3s timeout for health check

    local ok, res_or_err = pcall(function()
        return httpc:request_uri(health_url, { method = "GET" })
    end)

    if not ok then
        return false, "Connectivity error: " .. tostring(res_or_err)
    end

    local res = res_or_err
    if not res then
        return false, "No response from Keycloak"
    end

    if res.status == 200 then
        return true, "Keycloak reachable (realm exists)"
    elseif res.status == 404 then
        return false, "Realm '" .. realm_name .. "' not found on Keycloak"
    else
        return false, "Keycloak returned HTTP status " .. res.status
    end
end

local function fetch_jwks_from_keycloak()
    local kc_url = ENV_KC_INTERNAL_URL or ENV_KC_URL
    local realm_name = ENV_KC_REALM_NAME

    if not kc_url or not realm_name then
        ngx.log(ngx.ERR, "KC_URL/REALM_NAME must be set to fetch JWKS")
        return nil
    end

    local jwks_url = kc_url .. "/realms/" .. realm_name ..
                      "/.well-known/openid-configuration"
    ngx.log(ngx.INFO, "Fetching OIDC configuration from: ", jwks_url)

    local httpc = http.new()
    httpc:set_timeout(5000) -- 5s timeout

    local ok, res_or_err = pcall(function()
        return httpc:request_uri(jwks_url, {
            method = "GET",
            headers = { ["Accept"] = "application/json" }
        })
    end)

    if not ok then
        ngx.log(ngx.ERR, "OIDC config fetch error: ", res_or_err)
        return nil
    end

    local res = res_or_err
    if not res then
        ngx.log(ngx.ERR, "No response fetching OIDC config")
        return nil
    end
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "OIDC config HTTP error: ", res.status)
        return nil
    end

    local config_ok, oidc_config = pcall(cjson.decode, res.body)
    if not config_ok or not oidc_config.jwks_uri then
        ngx.log(ngx.ERR, "Invalid OIDC config or missing jwks_uri")
        return nil
    end

    ngx.log(ngx.INFO, "Fetching JWKs from: ", oidc_config.jwks_uri)
    local jwks_ok, jwks_res_or_err = pcall(function()
        return httpc:request_uri(oidc_config.jwks_uri, {
            method = "GET",
            headers = { ["Accept"] = "application/json" }
        })
    end)

    if not jwks_ok then
        ngx.log(ngx.ERR, "JWKs fetch error: ", jwks_res_or_err)
        return nil
    end

    local jwks_res = jwks_res_or_err
    if not jwks_res then
        ngx.log(ngx.ERR, "No response fetching JWKs")
        return nil
    end
    if jwks_res.status ~= 200 then
        ngx.log(ngx.ERR, "JWKs HTTP error: ", jwks_res.status)
        return nil
    end

    local jwks_data_ok, jwks_data = pcall(cjson.decode, jwks_res.body)
    if not jwks_data_ok or not jwks_data.keys then
        ngx.log(ngx.ERR, "Invalid JWKs data")
        return nil
    end

    return jwks_data.keys
end

local function jwk_to_pem(jwk_key)
    if jwk_key.kty ~= "RSA" then
        ngx.log(ngx.ERR, "Only RSA keys are supported")
        return nil
    end
    if not jwk_key.n or not jwk_key.e then
        ngx.log(ngx.ERR, "Missing RSA parameters (n or e)")
        return nil
    end

    -- decode base64url params (not used directly here)
    local n_bytes = base64url_decode(jwk_key.n)
    local e_bytes = base64url_decode(jwk_key.e)
    if not n_bytes or not e_bytes then
        ngx.log(ngx.ERR, "Failed to decode RSA parameters")
        return nil
    end

    ngx.log(ngx.INFO, "JWK found - kid: ", jwk_key.kid, ", alg: ", jwk_key.alg or "N/A")

    -- Prefer x5c certificate when available and return PEM text
    if jwk_key.x5c and jwk_key.x5c[1] then
        local cert_b64 = jwk_key.x5c[1]
        local cert_pem = "-----BEGIN CERTIFICATE-----\n"
        for i = 1, #cert_b64, 64 do
            cert_pem = cert_pem .. cert_b64:sub(i, i + 63) .. "\n"
        end
        cert_pem = cert_pem .. "-----END CERTIFICATE-----"

        ngx.log(ngx.INFO, "Using X.509 certificate from JWK")
        return { certificate = cert_pem }
    end

    ngx.log(ngx.ERR, "Cannot build PEM from JWK parameters")
    return nil
end

local function load_public_key_from_keycloak()
    local keys = fetch_jwks_from_keycloak()
    if not keys then return nil end

    -- Find first usable RSA key for signature
    for _, key in ipairs(keys) do
        if key.kty == "RSA" and (key.use == "sig" or not key.use) then
            local key_data = jwk_to_pem(key)
            if key_data then
                local openssl = require "resty.openssl"
                local x509 = require "resty.openssl.x509"

                local cert, err = x509.new(key_data.certificate)
                if not cert then
                    ngx.log(ngx.ERR, "X.509 parse error: ", err)
                else
                    local pubkey = cert:get_pubkey()
                    if pubkey then
                        local pubkey_pem = pubkey:to_PEM("public")
                        if pubkey_pem then
                            -- Historically CloudFront signed cookies use RSA-SHA1.
                            -- Use SHA1 to match the signature generation.
                            local pub, rsa_err = resty_rsa:new({
                                public_key = pubkey_pem,
                                padding = resty_rsa.PADDING.RSA_PKCS1_PADDING,
                                algorithm = "SHA1"
                            })
                            if pub then
                                ngx.log(ngx.INFO, "Public key loaded from Keycloak (kid: ", key.kid, ")")
                                return pub
                            else
                                ngx.log(ngx.ERR, "Error creating RSA object: ", rsa_err)
                            end
                        else
                            ngx.log(ngx.ERR, "Failed to extract public key PEM")
                        end
                    else
                        ngx.log(ngx.ERR, "Failed to get public key from certificate")
                    end
                end
            end
        end
    end

    ngx.log(ngx.ERR, "No usable RSA key found in JWKs")
    return nil
end

local function load_public_key()
    -- Only load from Keycloak; no file fallback
    local key_from_kc = load_public_key_from_keycloak()
    if key_from_kc then return key_from_kc end

    ngx.log(ngx.ERR, "Failed to load public key from Keycloak")
    return nil
end

local function load_config()
    local current_time = ngx.time()

    -- Initialize summary once
    if config.status == "not_loaded" then
        config.status = "loaded"
        config.summary = {
            ENV_KC_URL = ENV_KC_URL or "ERROR",
            ENV_KC_INTERNAL_URL = ENV_KC_INTERNAL_URL or "ERROR",
            ENV_KC_REALM_NAME = ENV_KC_REALM_NAME or "ERROR",
            ENV_KC_CLIENT_ID = ENV_KC_CLIENT_ID or "ERROR",
            ENV_KC_CLIENT_SECRET = ENV_KC_CLIENT_SECRET and "SET" or "ERROR",
            ENV_KC_CF_SIGN_KEY_ID = ENV_KC_CF_SIGN_KEY_ID or "ERROR",
            ENV_DEBUG_PAGE_NO_AUTH = ENV_DEBUG_PAGE_NO_AUTH or "ERROR"
        }
    end

    -- Smart public key loading with retry
    if not config.public_key then
        if current_time - config.last_key_attempt >= config.key_retry_interval then
            ngx.log(ngx.INFO, "Attempting to fetch public key from Keycloak...")
            config.last_key_attempt = current_time

            local kc_accessible, kc_status_msg = check_keycloak_connectivity()
            if not kc_accessible then
                ngx.log(ngx.WARN, "Keycloak not reachable: ", kc_status_msg)
                config.summary.Public_Key_Keycloak = "ERROR - Keycloak not reachable: " .. kc_status_msg
                config.keycloak_connectivity_error = kc_status_msg
            else
                ngx.log(ngx.INFO, "Keycloak reachable, fetching keys...")
                config.public_key = load_public_key()
                config.keycloak_connectivity_error = nil
                if config.public_key then
                    ngx.log(ngx.INFO, "Public key fetched and cached")
                    config.summary.Public_Key_Keycloak = "Loaded from Keycloak (cached)"
                else
                    ngx.log(ngx.WARN, "Key fetch failed, next try in ", config.key_retry_interval, "s")
                    config.summary.Public_Key_Keycloak = "ERROR - Fetch failed, retry in " ..
                        config.key_retry_interval .. "s"
                end
            end
        else
            local time_until_retry = config.key_retry_interval - (current_time - config.last_key_attempt)
            if config.keycloak_connectivity_error then
                config.summary.Public_Key_Keycloak = "ERROR - Keycloak unreachable, retry in " ..
                    time_until_retry .. "s"
            else
                config.summary.Public_Key_Keycloak = "ERROR - Next attempt in " .. time_until_retry .. "s"
            end
        end
    else
        config.summary.Public_Key_Keycloak = "Loaded from Keycloak (cached)"
        config.keycloak_connectivity_error = nil
    end

    -- Check env vars validity
    if not ENV_KC_URL or not ENV_KC_INTERNAL_URL or not ENV_KC_REALM_NAME or
       not ENV_KC_CLIENT_ID or not ENV_KC_CLIENT_SECRET or not ENV_KC_CF_SIGN_KEY_ID or
       not ENV_DEBUG_PAGE_NO_AUTH then
        config.env_config_error = true
    else
        config.env_config_error = false
    end

    return config
end


local function replace_url_safe_chars(str)
    if not str then return nil end
    if not str then return nil end

    ngx.log(ngx.INFO, "Convert CloudFront safe URL chars from string: ", str)
    local res = str:gsub("-", "+"):gsub("_", "="):gsub("~", "/")
    ngx.log(ngx.INFO, "Converted string: ", res)
    return res
end


local function verify_signature(policy, signature, public_key)
    -- Log des données avant vérification
    ngx.log(ngx.INFO, "=== Début vérification signature ===")
    ngx.log(ngx.INFO, "Policy à vérifier: ", policy)
    ngx.log(ngx.INFO, "Signature à vérifier (base64): ", signature)

    -- Décoder la signature depuis base64
    local decoded_signature = ngx.decode_base64(replace_url_safe_chars(signature))
    if not decoded_signature then
        ngx.log(ngx.ERR, "Échec du décodage de la signature")
        return false
    end

    -- IMPORTANT : Utiliser la policy encodée d'origine pour la vérification
    -- Add diagnostic logs: lengths and sample bytes
    local sig_len = decoded_signature and #decoded_signature or 0
    local pol_len = policy and #policy or 0
    local function to_hex_prefix(s, n)
        if not s or s == "" then return "" end
        n = n or 8
        local pick = s:sub(1, n)
        local out = {}
        for i = 1, #pick do
            out[#out+1] = string.format("%02X", pick:byte(i))
        end
        return table.concat(out, "")
    end
    ngx.log(ngx.INFO, "Signature bytes length: ", sig_len, ", first bytes(hex): ", to_hex_prefix(decoded_signature, 12))
    ngx.log(ngx.INFO, "Policy text length: ", pol_len, ", first bytes(hex): ", to_hex_prefix(policy, 32))

    local verify_ok, err = public_key:verify(policy, decoded_signature)
    if not verify_ok then
        ngx.log(ngx.ERR, "Échec de la vérification de signature: ", err)
        return false
    end

    ngx.log(ngx.INFO, "Vérification de signature réussie")
    ngx.log(ngx.INFO, "=== Fin vérification signature ===")
    return true
end

function _M.check_auth()
    -- Protect against errors to avoid 502 responses
    local ok, result = pcall(function()
        return _M.check_auth_internal()
    end)

    if not ok then
        ngx.log(ngx.ERR, "Error in check_auth: ", result)
        -- Use unified error rendering
        local error_pages = require "error_pages"
        error_pages.serve_error_page("503", "Keycloak authentication server is not reachable.")
        ngx.exit(503)
    end

    -- If Keycloak is unavailable and we recently retried,
    -- render the error page here instead of proxying to nginx
    if result.keycloak_unavailable then
        local error_pages = require "error_pages"
        error_pages.serve_error_page("503", result.error_message)
        ngx.exit(503)
    end

    return result
end


function _M.check_auth_internal()
    local decoded_policy = nil

    -- List all cookies for debugging
    local all_cookies = ngx.req.get_headers()["cookie"]
    ngx.log(ngx.INFO, "All cookies: ", all_cookies)

    -- Direct retrieval of cookies by original names
    local cookie_policy = ngx.var["cookie_CloudFront-Policy"]
    local cookie_key_pair_id = ngx.var["cookie_CloudFront-Key-Pair-Id"]
    local cookie_signature = ngx.var["cookie_CloudFront-Signature"]

    ngx.log(ngx.INFO,
        "Checking cookies - Policy: ", cookie_policy,
        " Key-Pair-Id: ", cookie_key_pair_id,
        " Signature: ", cookie_signature
    )

    local debug_info = {
        cookies = {
            ["CloudFront-Policy"] = cookie_policy or false,
            ["CloudFront-Key-Pair-Id"] = cookie_key_pair_id or false,
            ["CloudFront-Signature"] = cookie_signature or false
        },
        verification_steps = {
            public_key = { status = "not_checked", message = "not_verifiable" },
            cookie_policy = { status = "not_checked", message = "not_verifiable" },
            cookie_key_pair_id = { status = "not_checked", message = "not_verifiable" },
            cookie_signature = { status = "not_checked", message = "not_verifiable" },
            cookie_key_pair_id_match = { status = "not_checked", message = "not_verifiable" },
            policy_decode = { status = "not_checked", message = "not_verifiable" },
            policy_json = { status = "not_checked", message = "not_verifiable" },
            expiration = { status = "not_checked", message = "not_verifiable" },
            signature_verify = { status = "not_checked", message = "not_verifiable" }
        },
        is_authenticated = true,
        auth_error = false
    }

    local cfg = load_config()

    -- Public key specific check with retry handling
    if not cfg.public_key then
        local current_time = ngx.time()
        local time_since_last_attempt = current_time - cfg.last_key_attempt

        local error_message
        if cfg.keycloak_connectivity_error then
            error_message = "Keycloak not reachable: " .. cfg.keycloak_connectivity_error ..
                ". Verify Keycloak is running and reachable."
        else
            error_message = "Failed to load public key from Keycloak. Check KC_URL, KC_REALM_NAME and network"
        end

        -- Return information so check_auth can render an error page
        return {
            is_authenticated = false,
            auth_error = true,
            keycloak_unavailable = true,
            error_message = error_message,
            technical_error = cfg.keycloak_connectivity_error or "Connectivity details not available",
            current_url = ngx.var.request_uri,
            config = cfg.summary,
            config_status = cfg.status
        }
    else
        debug_info.verification_steps["public_key"] = {
            status = "success",
            message = "Public key loaded from Keycloak (cached)"
        }
    end

    -- Verify other configuration parameters
    if cfg.env_config_error then
        debug_info.verification_steps["final"] = {
            status = "error",
            message = "Environment variable configuration error"
        }
        debug_info.is_authenticated = false
        debug_info.auth_error = true

        return {
            is_authenticated = debug_info.is_authenticated,
            auth_error = debug_info.auth_error,
            auth_status = debug_info.verification_steps["final"].status,
            debug_info = debug_info,
            current_url = ngx.var.request_uri,
            config = cfg.summary,
            config_status = cfg.status
        }
    end

    -- Check if all CloudFront cookies are absent (no error, just disconnected)
    if not cookie_policy and not cookie_key_pair_id and not cookie_signature then
        local no_cookie_info = { status = "error", message = "No CloudFront cookie found" }
        debug_info.verification_steps["cookie_policy"] = no_cookie_info
        debug_info.verification_steps["cookie_key_pair_id"] = no_cookie_info
        debug_info.verification_steps["cookie_signature"] = no_cookie_info
        debug_info.is_authenticated = false

        debug_info.verification_steps["final"] = { status = "warning", message = "No CloudFront cookie found" }
    else
        if not cookie_policy then
            debug_info.verification_steps["cookie_policy"] = {
                status = "error", message = "CloudFront-Policy cookie missing"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_policy"] = {
                status = "success",
                message = "CloudFront-Policy cookie present",
                value = cookie_policy
            }

            -- Try unescaping the cookie (handles %2B/%2F encodings) and normalize
            local raw_cookie = ngx.unescape_uri(cookie_policy)
            raw_cookie = raw_cookie and raw_cookie:gsub("%s+", "") or raw_cookie

            decoded_policy = ngx.decode_base64(replace_url_safe_chars(raw_cookie))
            if not decoded_policy then
                debug_info.verification_steps["policy_decode"] = { status = "error", message = "Policy decode failed" }
                ngx.log(ngx.ERR, "Policy decode failed for cookie value: ", tostring(cookie_policy))
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            else
                debug_info.verification_steps["policy_decode"] = {
                    status = "success",
                    message = "Policy decoded successfully",
                    value = decoded_policy
                }
            end

            -- Sanitize decoded policy before JSON parse (strip trailing junk like '?')
            local sanitized = extract_json_fragment(tostring(decoded_policy))
            local ok, policy_json = pcall(cjson.decode, sanitized)
            if not ok or not policy_json then
                -- Log decoded policy for debugging and try a tiny fallback (trim surrounding quotes)
                ngx.log(ngx.ERR, "Policy JSON parse failed. Decoded policy: ", tostring(decoded_policy))
                local fallback = decoded_policy and decoded_policy:gsub('^%s*"', ''):gsub('"%s*$', '') or decoded_policy
                local ok2, policy_json2 = pcall(cjson.decode, fallback)
                if ok2 and policy_json2 then
                    policy_json = policy_json2
                    decoded_policy = fallback
                end
            end

            if not policy_json then
                debug_info.verification_steps["policy_json"] = { status = "error", message = "Invalid policy JSON" }
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            else
                debug_info.verification_steps["policy_json"] = {
                    status = "success",
                    message = "Policy JSON parsed",
                    policy = policy_json,
                    raw_policy = decoded_policy
                }

                -- Check expiration only when policy JSON contains the expected fields
                local has_expiration = policy_json and policy_json.Statement and
                    policy_json.Statement[1] and policy_json.Statement[1].Condition and
                    policy_json.Statement[1].Condition.DateLessThan and
                    policy_json.Statement[1].Condition.DateLessThan["AWS:EpochTime"]

                if has_expiration then
                    local expiration = policy_json.Statement[1].Condition.DateLessThan["AWS:EpochTime"]
                    local current_time = ngx.time()

                    if current_time >= expiration then
                        debug_info.verification_steps["expiration"] = {
                            status = "error",
                            message = "Policy expired",
                            expiration = expiration,
                            current_time = current_time
                        }
                        debug_info.is_authenticated = false
                        -- If expired but other checks pass, it's not an auth_error
                    else
                        debug_info.verification_steps["expiration"] = {
                            status = "success",
                            message = "Expiration date valid",
                            expiration = expiration,
                            current_time = current_time
                        }
                    end
                else
                    -- Expiration not found in policy: mark as warning, do not set auth_error
                    debug_info.verification_steps["expiration"] = {
                        status = "warning",
                        message = "Expiration not found in policy"
                    }
                end
            end
        end

        if not cookie_key_pair_id then
            debug_info.verification_steps["cookie_key_pair_id"] = {
                status = "error",
                message = "CloudFront-Key-Pair-Id cookie missing"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_key_pair_id"] = {
                status = "success",
                message = "CloudFront-Key-Pair-Id cookie present",
                value = cookie_key_pair_id
            }

            if cookie_key_pair_id == ENV_KC_CF_SIGN_KEY_ID then
                debug_info.verification_steps["cookie_key_pair_id_match"] = {
                    status = "success",
                    message = "Key-Pair-Id matches configuration"
                }
            else
                debug_info.verification_steps["cookie_key_pair_id_match"] = {
                    status = "error",
                    message = "Key-Pair-Id does not match configured value"
                }
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            end
        end

        if not cookie_signature then
            debug_info.verification_steps["cookie_signature"] = {
                status = "error",
                message = "CloudFront-Signature cookie missing"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_signature"] = {
                status = "success",
                message = "CloudFront-Signature cookie present", value = cookie_signature
            }

            if decoded_policy and cfg.public_key then
                if not verify_signature(decoded_policy, cookie_signature, cfg.public_key) then
                    debug_info.verification_steps["signature_verify"] = {
                        status = "error",
                        message = "Invalid signature"
                    }
                    debug_info.is_authenticated = false
                    debug_info.auth_error = true
                else
                    debug_info.verification_steps["signature_verify"] = {
                        status = "success",
                        message = "Signature verified successfully"
                    }
                end
            end
        end

        -- If all checks passed
        if debug_info.is_authenticated then
            debug_info.verification_steps["final"] = { status = "success", message = "All checks passed" }
        elseif not debug_info.auth_error and debug_info.verification_steps["expiration"].status == "error" then
            debug_info.verification_steps["final"] = {
                status = "warning",
                message = "Authentication valid but expired"
            }
        else
            debug_info.verification_steps["final"] = {
                status = "error",
                message = "Some checks failed"
            }
        end
    end

    return {
        is_authenticated = debug_info.is_authenticated,
        auth_error = debug_info.auth_error,
        auth_status = debug_info.verification_steps["final"].status,
        debug_info = debug_info,
        current_url = ngx.var.request_uri,
        config = cfg.summary,
        config_status = cfg.status
    }
end -- end of check_auth_internal

return _M
