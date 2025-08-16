local _M = {}
local cjson = require "cjson"
local resty_rsa = require "resty.rsa"
local http = require "resty.http"

-- Variables d'environnement
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
    key_retry_interval = 5 -- Retry toutes les 5 secondes en cas d'échec
}

local function base64url_decode(str)
    -- Remplacer les caractères URL-safe par les caractères base64 standard
    str = str:gsub("-", "+"):gsub("_", "/")

    -- Ajouter le padding si nécessaire
    local padding = 4 - (#str % 4)
    if padding < 4 then
        str = str .. string.rep("=", padding)
    end

    return ngx.decode_base64(str)
end

local function check_keycloak_connectivity()
    local kc_url = os.getenv("KC_INTERNAL_URL") or os.getenv("KC_URL")
    local realm_name = os.getenv("KC_REALM_NAME")

    if not kc_url then
        return false, "KC_URL/KC_INTERNAL_URL non défini"
    end

    if not realm_name then
        return false, "KC_REALM_NAME non défini"
    end

    -- Utiliser l'endpoint des realms qui existe vraiment sur Keycloak
    local health_url = kc_url .. "/realms/" .. realm_name
    ngx.log(ngx.INFO, "Vérification connectivité Keycloak: ", health_url)

    local httpc = http.new()
    httpc:set_timeout(3000) -- 3 secondes de timeout pour la vérification

    local ok, res_or_err = pcall(function()
        return httpc:request_uri(health_url, {
            method = "GET"
        })
    end)

    if not ok then
        return false, "Erreur de connectivité: " .. tostring(res_or_err)
    end

    local res = res_or_err
    if not res then
        return false, "Pas de réponse du serveur Keycloak"
    end

    if res.status == 200 then
        return true, "Keycloak accessible (realm configuré)"
    elseif res.status == 404 then
        return false, "Realm '" .. realm_name .. "' non trouvé sur Keycloak"
    else
        return false, "Keycloak répond avec le statut HTTP " .. res.status
    end
end

local function fetch_jwks_from_keycloak()
    local kc_url = os.getenv("KC_INTERNAL_URL") or os.getenv("KC_URL")
    local realm_name = os.getenv("KC_REALM_NAME")

    if not kc_url or not realm_name then
        ngx.log(ngx.ERR, "KC_URL/KC_INTERNAL_URL et KC_REALM_NAME doivent être définis")
        return nil
    end

    local jwks_url = kc_url .. "/realms/" .. realm_name .. "/.well-known/openid-configuration"
    ngx.log(ngx.INFO, "Récupération de la configuration OIDC depuis: ", jwks_url)

    local httpc = http.new()
    httpc:set_timeout(5000) -- 5 secondes de timeout

    local ok, res_or_err = pcall(function()
        return httpc:request_uri(jwks_url, {
            method = "GET",
            headers = {
                ["Accept"] = "application/json"
            }
        })
    end)

    if not ok then
        ngx.log(ngx.ERR, "Erreur lors de la récupération de la configuration OIDC: ", res_or_err)
        return nil
    end

    local res = res_or_err
    if not res then
        ngx.log(ngx.ERR, "Pas de réponse lors de la récupération de la configuration OIDC")
        return nil
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "Erreur HTTP lors de la récupération de la configuration OIDC: ", res.status)
        return nil
    end

    local config_ok, oidc_config = pcall(cjson.decode, res.body)
    if not config_ok or not oidc_config.jwks_uri then
        ngx.log(ngx.ERR, "Configuration OIDC invalide ou jwks_uri manquant")
        return nil
    end

    ngx.log(ngx.INFO, "Récupération des clés JWK depuis: ", oidc_config.jwks_uri)

    local jwks_ok, jwks_res_or_err = pcall(function()
        return httpc:request_uri(oidc_config.jwks_uri, {
            method = "GET",
            headers = {
                ["Accept"] = "application/json"
            }
        })
    end)

    if not jwks_ok then
        ngx.log(ngx.ERR, "Erreur lors de la récupération des clés JWK: ", jwks_res_or_err)
        return nil
    end

    local jwks_res = jwks_res_or_err
    if not jwks_res then
        ngx.log(ngx.ERR, "Pas de réponse lors de la récupération des clés JWK")
        return nil
    end

    if jwks_res.status ~= 200 then
        ngx.log(ngx.ERR, "Erreur HTTP lors de la récupération des clés JWK: ", jwks_res.status)
        return nil
    end

    local jwks_data_ok, jwks_data = pcall(cjson.decode, jwks_res.body)
    if not jwks_data_ok or not jwks_data.keys then
        ngx.log(ngx.ERR, "Données JWK invalides")
        return nil
    end

    return jwks_data.keys
end

local function jwk_to_pem(jwk_key)
    if jwk_key.kty ~= "RSA" then
        ngx.log(ngx.ERR, "Seules les clés RSA sont supportées")
        return nil
    end

    if not jwk_key.n or not jwk_key.e then
        ngx.log(ngx.ERR, "Paramètres RSA manquants (n ou e)")
        return nil
    end

    -- Décoder les paramètres base64url
    local n_bytes = base64url_decode(jwk_key.n)
    local e_bytes = base64url_decode(jwk_key.e)

    if not n_bytes or not e_bytes then
        ngx.log(ngx.ERR, "Erreur lors du décodage des paramètres RSA")
        return nil
    end

    ngx.log(ngx.INFO, "Clé JWK trouvée - kid: ", jwk_key.kid, ", alg: ", jwk_key.alg or "N/A")

    -- Utiliser le certificat X.509 s'il est disponible, mais l'utiliser comme certificat complet
    if jwk_key.x5c and jwk_key.x5c[1] then
        local cert_b64 = jwk_key.x5c[1]
        local cert_pem = "-----BEGIN CERTIFICATE-----\n"

        -- Découper le base64 en lignes de 64 caractères
        for i = 1, #cert_b64, 64 do
            cert_pem = cert_pem .. cert_b64:sub(i, i + 63) .. "\n"
        end
        cert_pem = cert_pem .. "-----END CERTIFICATE-----"

        ngx.log(ngx.INFO, "Utilisation du certificat X.509 depuis JWK")
        return { certificate = cert_pem }
    end

    ngx.log(ngx.ERR, "Impossible de construire la clé PEM depuis les paramètres JWK")
    return nil
end

local function load_public_key_from_keycloak()
    local keys = fetch_jwks_from_keycloak()
    if not keys then
        return nil
    end

    -- Chercher la première clé RSA utilisable pour la signature
    for _, key in ipairs(keys) do
        if key.kty == "RSA" and (key.use == "sig" or not key.use) then
            local key_data = jwk_to_pem(key)
            if key_data then
                -- Créer l'objet RSA avec le certificat via openssl
                local openssl = require "resty.openssl"
                local x509 = require "resty.openssl.x509"

                -- Parser le certificat X.509
                local cert, err = x509.new(key_data.certificate)
                if not cert then
                    ngx.log(ngx.ERR, "Erreur parsing certificat X.509: ", err)
                else
                    -- Extraire la clé publique du certificat
                    local pubkey = cert:get_pubkey()
                    if pubkey then
                        local pubkey_pem = pubkey:to_PEM("public")
                        if pubkey_pem then
                            -- Créer l'objet RSA avec la clé publique extraite
                            local pub, rsa_err = resty_rsa:new({
                                public_key = pubkey_pem,
                                padding = resty_rsa.PADDING.RSA_PKCS1_PADDING,
                                algorithm = "SHA1"
                            })

                            if pub then
                                ngx.log(ngx.INFO, "Clé publique chargée avec succès depuis Keycloak (kid: ", key.kid, ")")
                                return pub
                            else
                                ngx.log(ngx.ERR, "Erreur lors de la création de l'objet RSA avec clé extraite: ", rsa_err)
                            end
                        else
                            ngx.log(ngx.ERR, "Erreur extraction clé publique en PEM")
                        end
                    else
                        ngx.log(ngx.ERR, "Erreur extraction clé publique du certificat")
                    end
                end
            end
        end
    end

    ngx.log(ngx.ERR, "Aucune clé RSA utilisable trouvée dans les JWK")
    return nil
end

local function load_public_key()
    -- Charger uniquement depuis Keycloak (plus de fallback fichier)
    local key_from_kc = load_public_key_from_keycloak()
    if key_from_kc then
        return key_from_kc
    end

    ngx.log(ngx.ERR, "Impossible de charger la clé publique depuis Keycloak")
    return nil
end

local function load_config()
    local current_time = ngx.time()

    -- Charger la configuration de base une seule fois
    if config.status == "not_loaded" then
        config.status = "loaded"
        config.summary = {
            ENV_KC_URL = ENV_KC_URL or "ERROR",
            ENV_KC_INTERNAL_URL = ENV_KC_INTERNAL_URL or "ERROR",
            ENV_KC_REALM_NAME = ENV_KC_REALM_NAME or "ERROR",
            ENV_KC_CLIENT_ID = ENV_KC_CLIENT_ID or "ERROR",
            ENV_KC_CLIENT_SECRET = ENV_KC_CLIENT_SECRET and "Défini" or "ERROR",
            ENV_KC_CF_SIGN_KEY_ID = ENV_KC_CF_SIGN_KEY_ID or "ERROR",
            ENV_DEBUG_PAGE_NO_AUTH = ENV_DEBUG_PAGE_NO_AUTH or "ERROR"
        }
    end

    -- Gestion intelligente de la clé publique avec retry
    if not config.public_key then
        -- Retry seulement si l'intervalle est écoulé
        if current_time - config.last_key_attempt >= config.key_retry_interval then
            ngx.log(ngx.INFO, "Tentative de récupération de la clé publique depuis Keycloak...")
            config.last_key_attempt = current_time

            -- Vérifier d'abord la connectivité à Keycloak
            local kc_accessible, kc_status_msg = check_keycloak_connectivity()
            if not kc_accessible then
                ngx.log(ngx.WARN, "Keycloak non accessible: ", kc_status_msg)
                config.summary.Public_Key_Keycloak = "ERREUR - Keycloak non accessible: " .. kc_status_msg
                config.keycloak_connectivity_error = kc_status_msg
            else
                ngx.log(ngx.INFO, "Keycloak accessible, récupération des clés...")
                config.public_key = load_public_key()
                config.keycloak_connectivity_error = nil

                if config.public_key then
                    ngx.log(ngx.INFO, "Clé publique récupérée et mise en cache avec succès")
                    config.summary.Public_Key_Keycloak = "Chargée depuis Keycloak (mise en cache)"
                else
                    ngx.log(ngx.WARN, "Échec récupération clé, prochaine tentative dans ", config.key_retry_interval,
                        " secondes")
                    config.summary.Public_Key_Keycloak = "ERREUR - Tentative échouée, retry automatique dans " ..
                    config.key_retry_interval .. "s"
                end
            end
        else
            local time_until_retry = config.key_retry_interval - (current_time - config.last_key_attempt)
            if config.keycloak_connectivity_error then
                config.summary.Public_Key_Keycloak = "ERREUR - Keycloak non accessible, retry dans " ..
                time_until_retry .. "s"
            else
                config.summary.Public_Key_Keycloak = "ERREUR - Prochaine tentative dans " .. time_until_retry .. "s"
            end
        end
    else
        -- Clé déjà en cache
        config.summary.Public_Key_Keycloak = "Chargée depuis Keycloak (en cache)"
        config.keycloak_connectivity_error = nil
    end

    -- Vérifier les autres paramètres de configuration
    if
        not ENV_KC_URL or not ENV_KC_INTERNAL_URL or not ENV_KC_REALM_NAME or
        not ENV_KC_CLIENT_ID or not ENV_KC_CLIENT_SECRET or not ENV_KC_CF_SIGN_KEY_ID or not ENV_DEBUG_PAGE_NO_AUTH
    then
        config.env_config_error = true
    else
        config.env_config_error = false
    end

    return config
end

local function replace_url_safe_chars(str)
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
    -- Protection contre les erreurs pour éviter les 502
    local ok, result = pcall(function()
        return _M.check_auth_internal()
    end)

    if not ok then
        ngx.log(ngx.ERR, "Erreur dans check_auth: ", result)
        -- Utiliser le système unifié d'erreurs
        local error_pages = require "error_pages"
        error_pages.serve_error_page("503", "Le serveur d'authentification Keycloak n'est pas accessible.")
        ngx.exit(503)
    end

    -- Si Keycloak n'est pas accessible et que nous avons fait un retry récemment,
    -- afficher directement la page d'erreur au lieu de laisser nginx faire le proxy
    if result.keycloak_unavailable then
        local error_pages = require "error_pages"
        error_pages.serve_error_page("503", result.error_message)
        ngx.exit(503)
    end

    return result
end

function _M.check_auth_internal()
    local decoded_policy = nil

    -- Liste de tous les cookies pour le débogage
    local all_cookies = ngx.req.get_headers()["cookie"]
    ngx.log(ngx.INFO, "All cookies: ", all_cookies)

    -- Récupération directe des cookies avec leur nom d'origine
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
            public_key = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            cookie_policy = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            cookie_key_pair_id = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            cookie_signature = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            cookie_key_pair_id_match = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            policy_decode = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            policy_json = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            expiration = {
                status = "not_checked",
                message = "Non vérifiable"
            },
            signature_verify = {
                status = "not_checked",
                message = "Non vérifiable"
            }
        },
        is_authenticated = true,
        auth_error = false
    }

    local cfg = load_config()

    -- Vérification spécifique de la clé publique avec gestion du retry
    if not cfg.public_key then
        local current_time = ngx.time()
        local time_since_last_attempt = current_time - cfg.last_key_attempt

        local error_message
        if cfg.keycloak_connectivity_error then
            error_message = "Keycloak non accessible: " ..
            cfg.keycloak_connectivity_error .. ". Vérifiez que Keycloak est démarré et accessible."
        else
            error_message =
            "Impossible de charger la clé publique depuis Keycloak. Vérifiez la configuration KC_URL, KC_REALM_NAME et la connectivité réseau."
        end

        -- Retourner les informations pour que check_auth puisse afficher la page d'erreur
        return {
            is_authenticated = false,
            auth_error = true,
            keycloak_unavailable = true,
            error_message = error_message,
            technical_error = cfg.keycloak_connectivity_error or "Détails de connectivité non disponibles",
            current_url = ngx.var.request_uri,
            config = cfg.summary,
            config_status = cfg.status
        }
    else
        debug_info.verification_steps["public_key"] = {
            status = "success",
            message = "Clé publique chargée depuis Keycloak (en cache)"
        }
    end

    -- Vérification des autres paramètres de configuration
    if cfg.env_config_error then
        debug_info.verification_steps["final"] = {
            status = "error",
            message = "Erreur de configuration des variables d'environnement"
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
        local no_cookie_info = {
            status = "error",
            message = "Aucun cookie CloudFront trouvé"
        }
        debug_info.verification_steps["cookie_policy"] = no_cookie_info
        debug_info.verification_steps["cookie_key_pair_id"] = no_cookie_info
        debug_info.verification_steps["cookie_signature"] = no_cookie_info
        debug_info.is_authenticated = false

        debug_info.verification_steps["final"] = {
            status = "warning",
            message = "Aucun cookie CloudFront trouvé"
        }
    else
        if not cookie_policy then
            debug_info.verification_steps["cookie_policy"] = {
                status = "error",
                message = "Cookie CloudFront-Policy manquant"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_policy"] = {
                status = "success",
                message = "Cookie CloudFront-Policy présent",
                value = cookie_policy
            }

            decoded_policy = ngx.decode_base64(replace_url_safe_chars(cookie_policy))
            if not decoded_policy then
                debug_info.verification_steps["policy_decode"] = {
                    status = "error",
                    message = "Échec du décodage de la policy"
                }
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            else
                debug_info.verification_steps["policy_decode"] = {
                    status = "success",
                    message = "Policy décodée avec succès",
                    value = decoded_policy
                }
            end

            local ok, policy_json = pcall(cjson.decode, decoded_policy)
            if not ok or not policy_json then
                debug_info.verification_steps["policy_json"] = {
                    status = "error",
                    message = "Policy JSON invalide"
                }
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            else
                debug_info.verification_steps["policy_json"] = {
                    status = "success",
                    message = "Policy décodée avec succès",
                    policy = policy_json,
                    raw_policy = decoded_policy
                }
            end

            -- Vérification de l'expiration
            local expiration = policy_json.Statement[1].Condition.DateLessThan["AWS:EpochTime"]
            local current_time = ngx.time()

            if current_time >= expiration then
                debug_info.verification_steps["expiration"] = {
                    status = "error",
                    message = "Policy expirée",
                    expiration = expiration,
                    current_time = current_time
                }
                debug_info.is_authenticated = false
                -- If expired but others checks pass, is not auth_error
            else
                debug_info.verification_steps["expiration"] = {
                    status = "success",
                    message = "Date d'expiration valide",
                    expiration = expiration,
                    current_time = current_time
                }
            end
        end

        if not cookie_key_pair_id then
            debug_info.verification_steps["cookie_key_pair_id"] = {
                status = "error",
                message = "Cookie CloudFront-Key-Pair-Id manquant"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_key_pair_id"] = {
                status = "success",
                message = "Cookie CloudFront-Key-Pair-Id présent",
                value = cookie_key_pair_id
            }

            if cookie_key_pair_id == os.getenv("KC_CF_SIGN_KEY_ID") then
                debug_info.verification_steps["cookie_key_pair_id_match"] = {
                    status = "success",
                    message = "Cookie CloudFront-Key-Pair-Id correspond à la configuration"
                }
            else
                debug_info.verification_steps["cookie_key_pair_id_match"] = {
                    status = "error",
                    message = "Cookie CloudFront-Key-Pair-Id ne correspond pas à la configuration"
                }
                debug_info.is_authenticated = false
                debug_info.auth_error = true
            end
        end

        if not cookie_signature then
            debug_info.verification_steps["cookie_signature"] = {
                status = "error",
                message = "Cookie CloudFront-Signature manquant"
            }
            debug_info.is_authenticated = false
            debug_info.auth_error = true
        else
            debug_info.verification_steps["cookie_signature"] = {
                status = "success",
                message = "Cookie CloudFront-Signature présent",
                value = cookie_signature
            }

            if decoded_policy and cfg.public_key then
                if not verify_signature(decoded_policy, cookie_signature, cfg.public_key) then
                    debug_info.verification_steps["signature_verify"] = {
                        status = "error",
                        message = "Signature invalide"
                    }
                    debug_info.is_authenticated = false
                    debug_info.auth_error = true
                else
                    debug_info.verification_steps["signature_verify"] = {
                        status = "success",
                        message = "Signature vérifiée avec succès"
                    }
                end
            end
        end

        -- Si toutes les vérifications sont passées
        if debug_info.is_authenticated then
            debug_info.verification_steps["final"] = {
                status = "success",
                message = "Toutes les vérifications sont passées"
            }
        elseif not debug_info.auth_error and debug_info.verification_steps["expiration"].status == "error" then
            debug_info.verification_steps["final"] = {
                status = "warning",
                message = "L'authentification est valide mais expirée"
            }
        else
            debug_info.verification_steps["final"] = {
                status = "error",
                message = "Certaines vérifications ont échoué"
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
end -- Fin de check_auth_internal

return _M
