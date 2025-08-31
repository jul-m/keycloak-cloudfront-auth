<html>
<head>
    <title>${msg("redirectToAuthService")}</title>
    <style type="text/css">
        body {
            font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: silver;
        }
    </style>
    <meta id="refresh-meta" http-equiv="refresh" content="${redirectFallbackDelay}; URL=${authUrl}" />
</head>
<body>
    <noscript>
        <h5>${msg("javascriptDisabledWarning")}</h5>
    </noscript>
    <p><i>${msg("redirectToAuthService")}</i> <a href="${authUrl}" id="redirect-link">${msg("clickHereIfNoRedirect")}</a></p>
    <script>
        var currentUrl = window.location.href;
        var redirectUri = window.location.origin + "${redirectUriPath}?original_uri=" + encodeURIComponent(currentUrl);
        var authUrl = "${authUrl}".replace(/redirect_uri=([^&]*)/, 'redirect_uri=' + encodeURIComponent(redirectUri));
        var redirectDelay = parseInt("${redirectDelay}") * 1000;

        document.getElementById("redirect-link").href = authUrl;
        document.getElementById("refresh-meta").content = "${redirectFallbackDelay}; URL=" + authUrl;

        setTimeout(() => {  window.location.href = authUrl; }, redirectDelay);
    </script>
</body>
</html>
