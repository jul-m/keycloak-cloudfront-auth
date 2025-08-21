package fr.julm.keycloak.providers.auth.cloudfront;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.keycloak.forms.login.freemarker.model.UrlBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.theme.Theme;
import freemarker.template.TemplateMethodModelEx;
import freemarker.template.TemplateModelException;

import freemarker.template.Configuration;
import freemarker.template.Template;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class CloudFrontTemplate {
    public static final CacheControl CACHE_CONTROL_NO_CACHE = CacheControlUtil.noCache();

    private static final Logger logger = Logger.getLogger(CloudFrontTemplate.class);
    private static final ClassLoader classLoader = CloudFrontTemplate.class.getClassLoader();
    private static final Properties providerMessages = new Properties();
    private static final Configuration cfgClassLoader = new Configuration(Configuration.VERSION_2_3_32);
    private static final Map<String, TemplateMethodModelEx> messageFormattersCache = new ConcurrentHashMap<>();
    private static final Map<String, UrlBean> urlBeansCache = new ConcurrentHashMap<>();

    private Template template;

    // TODO: Configuration for overrides in themes/ folder

    static {
        cfgClassLoader.setClassLoaderForTemplateLoading(classLoader, "/html");
        try {
            providerMessages.load(classLoader.getResourceAsStream("messages/messages_en.properties"));
        }
        catch (Exception e) {
            logger.errorf("Error loading messages from properties file", e);
            throw new RuntimeException("Error loading messages from properties file", e);
        }
    }

    public CloudFrontTemplate(String templateName) {
        try {
            this.template = cfgClassLoader.getTemplate(templateName);
        }
        catch (Exception e) {
            logger.errorf("Error loading template %s", templateName, e);
            throw new RuntimeException("Error loading template " + templateName, e);
        }
    }

    private String getCacheKey(RealmModel realm, Theme theme, Locale locale) {
        return realm.getId() + ":" + theme.getName() + ":" + locale.toString();
    }

    private TemplateMethodModelEx getMessageFormatter(Theme theme, Locale locale) {
        String cacheKey = theme.getName() + ":" + locale.toString();
        return messageFormattersCache.computeIfAbsent(cacheKey, k -> {
            try {
                Properties messages = theme.getMessages(locale);
                // Merge provider specific messages
                messages.putAll(providerMessages);

                // Return a simple Freemarker method that looks up messages by key
                // and returns the raw string value (preserving apostrophes and
                // avoiding MessageFormat processing which can remove single quotes).
                return new TemplateMethodModelEx() {
                    @Override
                    public Object exec(java.util.List args) throws TemplateModelException {
                        if (args == null || args.isEmpty()) return "";
                        Object first = args.get(0);
                        if (first == null) return "";
                        String key = first.toString();
                        String v = messages.getProperty(key);
                        return v == null ? key : v;
                    }
                };
            }
            catch (IOException e) {
                logger.error("Error loading messages for theme: " + theme.getName() + " and locale: " + locale, e);
                throw new RuntimeException("Error loading messages", e);
            }
        });
    }

    private UrlBean getUrlBean(KeycloakSession session, RealmModel realm, Theme theme) {
        String cacheKey = getCacheKey(realm, theme, session.getContext().resolveLocale(null));
        return urlBeansCache.computeIfAbsent(cacheKey, k -> 
            new UrlBean(realm, theme, session.getContext().getUri().getBaseUri(), null)
        );
    }

    public String render(KeycloakSession session, Map<String, Object> attributes) {
        // https://github.com/keycloak/keycloak/blob/release/26.0/services/src/main/java/org/keycloak/services/error/KeycloakErrorHandler.java
        try {
            // S'assurer que le realm est défini dans la session
            if (session.getContext().getRealm() == null) {
                session.getContext().setRealm(session.realms().getRealmByName("master"));
            }

            RealmModel realm = session.getContext().getRealm();
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);

            // Obtenir la locale
            Locale locale = session.getContext().resolveLocale(null);
            if (locale == null) {
                locale = Locale.ENGLISH;
            }

            // Get real Keycloak base URL for load assets directly
            String keycloakBaseUrl = session.getContext().getUri().getBaseUri().toString();
            if (keycloakBaseUrl.endsWith("/")) {
                keycloakBaseUrl = keycloakBaseUrl.substring(0, keycloakBaseUrl.length() - 1);
            }

            // Functions attributes using cache
            attributes.put("msg", getMessageFormatter(theme, locale));
            attributes.put("url", getUrlBean(session, realm, theme));

            // Variables attributes
            attributes.put("properties", theme.getProperties()); 
            attributes.put("lang", locale.getLanguage());
            attributes.put("realm", realm);

            // keycloak-cloudfront-auth specific for get assets from Keycloak domain
            attributes.put("keycloakBaseUrl", keycloakBaseUrl);

            StringWriter sw = new StringWriter();
            template.process(attributes, sw);
            return sw.toString();
        }
        catch (Exception e) {
            logger.errorf("Error processing template %s", template, e);
            throw new RuntimeException("Error processing template " + template, e);
        }
    }

    public Response serve(KeycloakSession session, Map<String, Object> attributes, Response.Status status) {
        try {
            String html = render(session, attributes);
                
            return Response.status(status)
                           .type(MediaType.TEXT_HTML_TYPE)
                           .cacheControl(CACHE_CONTROL_NO_CACHE)
                           .entity(html)
                           .build();
        }
        catch (Exception e) {
            logger.error("Failed to render and serve template.", e);
            return basicInternalServerErrorPage();
        }
    }

    public static Response basicInternalServerErrorPage() {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                       .type(MediaType.TEXT_HTML_TYPE)
                       .cacheControl(CACHE_CONTROL_NO_CACHE)
                       .entity("Internal Server Error")
                       .build();
    }
}
