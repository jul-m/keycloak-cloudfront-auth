<!DOCTYPE html> <#-- https://github.com/keycloak/keycloak/blob/release/26.0/themes/src/main/resources/theme/keycloak.v2/login/template.ftl -->
<html class="${properties.kcHtmlClass!}" lang="${lang}">

<head>
  <title>${msg("errorTitle")}</title>
  <meta charset="utf-8">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="robots" content="noindex, nofollow">

  <#if properties.meta?has_content>
      <#list properties.meta?split(' ') as meta>
          <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
      </#list>
  </#if>
  <link rel="icon" href="${keycloakBaseUrl}${url.resourcesPath}/img/favicon.ico" />
  <#if properties.stylesCommon?has_content>
      <#list properties.stylesCommon?split(' ') as style>
          <link href="${keycloakBaseUrl}${url.resourcesCommonPath}/${style}" rel="stylesheet" />
      </#list>
  </#if>
  <#if properties.styles?has_content>
      <#list properties.styles?split(' ') as style>
          <link href="${keycloakBaseUrl}${url.resourcesPath}/${style}" rel="stylesheet" />
      </#list>
  </#if>
  <script type="importmap">
      {
          "imports": {
              "rfc4648": "${keycloakBaseUrl}${url.resourcesCommonPath}/vendor/rfc4648/rfc4648.js"
          }
      }
  </script>
  <#if properties.scripts?has_content>
      <#list properties.scripts?split(' ') as script>
          <script src="${keycloakBaseUrl}${url.resourcesPath}/${script}" type="text/javascript"></script>
      </#list>
  </#if>
  <#if scripts??>
      <#list scripts as script>
          <script src="${script}" type="text/javascript"></script>
      </#list>
  </#if>
  <script type="module">
      const DARK_MODE_CLASS = "pf-v5-theme-dark";
      const mediaQuery =window.matchMedia("(prefers-color-scheme: dark)");
      updateDarkMode(mediaQuery.matches);
      mediaQuery.addEventListener("change", (event) =>
        updateDarkMode(event.matches),
      );
      function updateDarkMode(isEnabled) {
        const { classList } = document.documentElement;
        if (isEnabled) {
          classList.add(DARK_MODE_CLASS);
        } else {
          classList.remove(DARK_MODE_CLASS);
        }
      }
  </script>
  <style type="text/css">
    #footer-cf-request-id {
      position: absolute; 
      bottom: 0; 
      text-align: center; 
      width: 100%; 
      font-weight: 100;
      color: grey;
    }
  </style>
</head>

<body id="keycloak-bg" class="${properties.kcBodyClass!}">

  <div class="${properties.kcLogin!}">
    <div class="${properties.kcLoginContainer!properties.kcLoginClass!}">
      <header
        id="kc-header"
        class="pf-v5-c-login__header${properties.kcHeaderClass?has_content?then(' ' + properties.kcHeaderClass, '')}"
      >
        <div id="kc-header-wrapper" class="pf-v5-c-brand">
          ${(realm.displayNameHtml?has_content)?then(realm.displayNameHtml, (realm.displayName?has_content)?then(realm.displayName, realm.name))}
        </div>
      </header>
      <main class="${properties.kcLoginMain!properties.kcFormCardClass!}">
        <div class="${properties.kcLoginMainHeader!properties.kcFormHeaderClass!}">
          <h1 class="${properties.kcLoginMainTitle!}" id="kc-page-title">${msg("errorTitle")}</h1>
        </div>
        <div class="${properties.kcLoginMainBody!}">
          <div id="kc-error-message">
            <p class="instruction">${msg(message)}</p>
          </div>
        </div>
        <div class="pf-v5-c-login__main-footer"></div>
      </main>
    </div>
  </div>
  <#if cfRequestId??>
  <div id="footer-cf-request-id">
    <p><i>Request ID: ${cfRequestId}</i></p>
  </div>
  </#if>
</body>
</html>