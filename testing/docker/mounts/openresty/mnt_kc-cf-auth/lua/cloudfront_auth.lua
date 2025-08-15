local _M = {}
local cjson = require "cjson"
local resty_rsa = require "resty.rsa"

local config = {
    status = "not_loaded"
}

local function load_public_key()
    local f = io.open("/mnt/kc-cf-auth/certs/cloudfront-public-key.pem", "r")
    if not f then
        ngx.log(ngx.ERR, "Impossible de charger la clé publique CloudFront")
        return nil
    end
    local key_content = f:read("*all")
    f:close()

    -- Vérification que nous avons bien une clé publique
    if not key_content:match("%-%-%-%-%-BEGIN PUBLIC KEY%-%-%-%-%-") then
        ngx.log(ngx.ERR, "Le fichier ne contient pas une clé publique valide")
        return nil
    end

    ngx.log(ngx.INFO, "=== Début contenu clé publique ===")
    ngx.log(ngx.INFO, key_content)
    ngx.log(ngx.INFO, "=== Fin contenu clé publique ===")

    -- Créer l'objet de clé publique RSA avec SHA1 comme algorithme
    local pub, err = resty_rsa:new({
        public_key = key_content,
        padding = resty_rsa.PADDING.RSA_PKCS1_PADDING,
        algorithm = "SHA1"
    })

    if not pub then
        ngx.log(ngx.ERR, "Erreur lors de la création de l'objet de clé publique: ", err)
        return nil
    end

    return pub
end

local function load_config()
    if config.status == "not_loaded" then
        config.status = "loaded"
        config.public_key = load_public_key()
        config.summary = {
            FILE_Public_Key = config.public_key and "Chargée" or "ERROR",
            ENV_KC_URL = ENV_KC_URL or "ERROR",
            ENV_KC_REALM_NAME = ENV_KC_REALM_NAME or "ERROR",
            ENV_KC_CLIENT_ID = ENV_KC_CLIENT_ID or "ERROR",
            ENV_KC_CLIENT_SECRET = ENV_KC_CLIENT_SECRET and "Défini" or "ERROR",
            ENV_KC_CF_SIGN_KEY_ID = ENV_KC_CF_SIGN_KEY_ID or "ERROR",
            ENV_DEBUG_PAGE_NO_AUTH = ENV_DEBUG_PAGE_NO_AUTH or "ERROR"
        }

        if
            not config.public_key or not ENV_KC_URL or not ENV_KC_REALM_NAME or not ENV_KC_CLIENT_ID or
            not ENV_KC_CLIENT_SECRET or not ENV_KC_CF_SIGN_KEY_ID or not ENV_DEBUG_PAGE_NO_AUTH
        then
            config.status = "error"
        end

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
    if cfg.status == "error" then
        debug_info.verification_steps["final"] = {
            status = "error",
            message = "Erreur de configuration"
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

    if not cfg.public_key then
        debug_info.verification_steps["public_key"] = {
            status = "error",
            message = "Impossible de charger la clé publique"
        }
        debug_info.is_authenticated = false
        debug_info.auth_error = true
    else
        debug_info.verification_steps["public_key"] = {
            status = "success",
            message = "Clé publique chargée avec succès"
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
end

return _M