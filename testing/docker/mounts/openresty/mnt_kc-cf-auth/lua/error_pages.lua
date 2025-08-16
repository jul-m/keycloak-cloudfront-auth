-- Module pour générer les pages d'erreur dynamiques
local _M = {}

-- Configuration des templates d'erreur
local error_configs = {
    ["502"] = {
        PAGE_TITLE = "Service d'authentification indisponible",
        ERROR_CODE = "502",
        ERROR_TITLE = "Service d'Authentification Indisponible",
        ERROR_DESCRIPTION = "Le service d'authentification Keycloak ne répond pas actuellement.",
        TECHNICAL_INFO =
        "• Vérification de connectivité Keycloak échouée<br>• Cause probable : Keycloak non démarré ou problème réseau<br>• Erreur : Bad Gateway (502)",
        AUTO_RETRY = "true",
    },
    ["503"] = {
        PAGE_TITLE = "Service Temporairement Indisponible",
        ERROR_CODE = "503",
        ERROR_TITLE = "Service Temporairement Indisponible",
        ERROR_DESCRIPTION = "Le service est temporairement indisponible pour maintenance ou surcharge.",
        TECHNICAL_INFO =
        "• Service en maintenance ou surchargé<br>• Retry automatique activé<br>• Erreur : Service Unavailable (503)",
        AUTO_RETRY = "true",
    },
    ["504"] = {
        PAGE_TITLE = "Délai d'attente dépassé",
        ERROR_CODE = "504",
        ERROR_TITLE = "Délai d'Attente Dépassé",
        ERROR_DESCRIPTION = "Le serveur n'a pas répondu dans les délais impartis.",
        TECHNICAL_INFO =
        "• Timeout de la passerelle dépassé<br>• Possible surcharge temporaire<br>• Erreur : Gateway Timeout (504)",
        AUTO_RETRY = "true",
    },
    ["500"] = {
        PAGE_TITLE = "Erreur interne du serveur",
        ERROR_CODE = "500",
        ERROR_TITLE = "Erreur Interne du Serveur",
        ERROR_DESCRIPTION = "Une erreur interne s'est produite sur le serveur.",
        TECHNICAL_INFO =
        "• Erreur interne du serveur<br>• Logs à consulter pour diagnostic<br>• Erreur : Internal Server Error (500)",
        AUTO_RETRY = "false",
    }
}

-- Fonction pour générer une page d'erreur
function _M.generate_error_page(error_code, custom_message)
    local config = error_configs[tostring(error_code)]
    if not config then
        config = error_configs["500"] -- Fallback vers erreur 500
    end

    -- Personnalisation du message si fourni
    if custom_message then
        config.ERROR_DESCRIPTION = custom_message
    end

    -- Lecture du template unifié
    local template_file = io.open("/mnt/kc-cf-auth/html/error.html", "r")
    if not template_file then
        return nil, "Template file not found"
    end

    local template_content = template_file:read("*all")
    template_file:close()

    -- Remplacement des variables
    for key, value in pairs(config) do
        local pattern = "{{" .. key .. "}}"
        template_content = string.gsub(template_content, pattern, value)
    end

    return template_content, nil
end

-- Fonction pour servir une page d'erreur via nginx
function _M.serve_error_page(error_code, custom_message)
    local page_content, err = _M.generate_error_page(error_code, custom_message)

    if err then
        ngx.status = 500
        ngx.say("Error generating error page: " .. err)
        return
    end

    ngx.status = tonumber(error_code) or 500
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(page_content)
end

return _M
