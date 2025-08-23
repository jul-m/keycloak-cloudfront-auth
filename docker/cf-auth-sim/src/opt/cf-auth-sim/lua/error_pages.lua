-- Module to generate dynamic error pages for the nginx simulator.
local _M = {}

-- Error template configurations keyed by HTTP status code.
-- Values are strings used to replace {{KEY}} placeholders in the
-- shared HTML template mounted at /opt/cf-auth-sim/html/error.html.
local error_configs = {
    ["502"] = {
        PAGE_TITLE = "Authentication Service Unavailable",
        ERROR_CODE = "502",
        ERROR_TITLE = "Authentication Service Unavailable",
        ERROR_DESCRIPTION = "The Keycloak auth service is not responding.",
        TECHNICAL_INFO =
            "• Keycloak connectivity check failed<br>" ..
            "• Likely cause: Keycloak is down or network issue<br>" ..
            "• Error: Bad Gateway (502)",
        AUTO_RETRY = "true",
    },
    ["503"] = {
        PAGE_TITLE = "Service Temporarily Unavailable",
        ERROR_CODE = "503",
        ERROR_TITLE = "Service Temporarily Unavailable",
        ERROR_DESCRIPTION =
            "The service is temporarily unavailable due to maintenance or load.",
        TECHNICAL_INFO =
            "• Service under maintenance or overloaded<br>" ..
            "• Automatic retry enabled<br>" ..
            "• Error: Service Unavailable (503)",
        AUTO_RETRY = "true",
    },
    ["504"] = {
        PAGE_TITLE = "Gateway Timeout",
        ERROR_CODE = "504",
        ERROR_TITLE = "Gateway Timeout",
        ERROR_DESCRIPTION = "The upstream server did not respond in time.",
        TECHNICAL_INFO =
            "• Gateway timeout occurred<br>" ..
            "• Possible temporary overload<br>" ..
            "• Error: Gateway Timeout (504)",
        AUTO_RETRY = "true",
    },
    ["500"] = {
        PAGE_TITLE = "Internal Server Error",
        ERROR_CODE = "500",
        ERROR_TITLE = "Internal Server Error",
        ERROR_DESCRIPTION = "An internal server error occurred.",
        TECHNICAL_INFO =
            "• Internal server error<br>" ..
            "• Check logs for diagnosis<br>" ..
            "• Error: Internal Server Error (500)",
        AUTO_RETRY = "false",
    },
}


-- Generate the error page content from the HTML template.
-- error_code: number or string
-- custom_message: optional string to override the description
function _M.generate_error_page(error_code, custom_message)
    local config = error_configs[tostring(error_code)]
    if not config then
        config = error_configs["500"] -- fallback to 500
    end

    if custom_message then
        config.ERROR_DESCRIPTION = custom_message
    end

    -- Read the shared template file from the mounted volume.
    local template_file = io.open("/opt/cf-auth-sim/html/error.html", "r")
    if not template_file then
        return nil, "Template file not found"
    end

    local template_content = template_file:read("*all")
    template_file:close()

    -- Replace placeholders like {{KEY}} with values from config.
    for key, value in pairs(config) do
        local pattern = "{{" .. key .. "}}"
        template_content = string.gsub(template_content, pattern, value)
    end

    return template_content, nil
end


-- Serve the generated error page via nginx.
-- Sets the response status and Content-Type header and writes the body.
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
