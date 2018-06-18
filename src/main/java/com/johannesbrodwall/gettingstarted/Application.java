package com.johannesbrodwall.gettingstarted;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Application {

    private static Logger logger = LoggerFactory.getLogger(Application.class);

    private Properties properties = new Properties();

    private static class GoogleAuthenticationServlet extends HttpServlet {

        private String clientId;
        private String clientSecret;

        public GoogleAuthenticationServlet(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            if ("/login".equals(req.getPathInfo())) {
                resp.sendRedirect(getAuthenticationUrl(getRedirectUri(req)));
                return;
            }

            if ("/oauth2callback".equals(req.getPathInfo())) {
                HttpURLConnection conn = postForm(new URL("https://accounts.google.com/o/oauth2/token"),
                        tokenQuery(getRedirectUri(req), req.getParameter("code")));
                JsonObject tokenResponse = JsonParser.parseToObject(conn);

                resp.setContentType("text/html");
                resp.getWriter().write("<body>\n");
                writeTokenResponse(resp.getWriter(), tokenResponse);
                String accessToken = tokenResponse.requiredString("access_token");
                JsonObject jsonProfile = getProfile(accessToken);
                resp.getWriter().write("\n\n<h2>Profile</h2>\n\n" + writeTextArea(jsonProfile));
                resp.getWriter().write("<p><a href='/'>Front page</a></p>");
                resp.getWriter().write("</body>\n");
            }
        }

        private String getAuthenticationUrl(String redirectUri) {
            return "https://accounts.google.com/o/oauth2/v2/auth?"
                    + "redirect_uri=" + redirectUri
                    + "&response_type=code"
                    + "&scope=https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile"
                    + "&client_id=" + clientId;
        }

        private JsonObject getProfile(String accessToken) throws MalformedURLException, IOException {
            return JsonParser.parseToObject(new URL("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + accessToken));
        }

        private String tokenQuery(String redirectUri, String code) {
            return "code=" + code
                    + "&client_id=" + clientId + "&client_secret=" + clientSecret +
                    "&redirect_uri=" + redirectUri + "&grant_type=authorization_code";
        }

        private String getRedirectUri(HttpServletRequest req) {
            return getBaseUrl(req) + req.getContextPath() + req.getServletPath() + "/oauth2callback";
        }
    }

    private static class MultiTenantActiveDirectoryServlet extends HttpServlet {
        private String tenantId;
        private String clientId;
        private String clientSecret;

        public MultiTenantActiveDirectoryServlet(String clientId, String clientSecret, String tenantId) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tenantId = tenantId;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            PrintWriter writer = resp.getWriter();
            if (req.getPathInfo().equals("/login")) {
                if (req.getParameter("prompt") != null) {
                    resp.sendRedirect(getAutheticationUrl(getRedirectUri(req), "offline_access+openid+profile+User.Read+Directory.Read.All+Group.Read.All"));
                    return;
                }
                String autheticationUrl = getAutheticationUrl(getRedirectUri(req),
                        "offline_access+openid+profile+User.Read");
                if (req.getParameter("domain_hint") != null) {
                    autheticationUrl += "&domain_hint=" + req.getParameter("domain_hint");
                }
                logger.info("Redirecting to {}", autheticationUrl);
                resp.sendRedirect(autheticationUrl);
                return;
            }

            String scope = req.getParameter("scope");
            String accessToken = req.getParameter("access_token");
            if (req.getPathInfo().equals("/profile")) {
                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeActions(writer, accessToken, scope);
                writer.write("<h2>Profile response</h2>");
                writer.write(writeTextArea(makeGetRequest(new URL("https://graph.microsoft.com/v1.0/me"), accessToken)));
                return;
            }

            if (req.getPathInfo().equals("/members")) {
                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeActions(writer, accessToken, scope);
                writer.write("<h2>Group members</h2>");
                writer.write(writeTextArea(makeGetRequest(new URL("https://graph.microsoft.com/v1.0/groups/" + req.getParameter("group") + "/members"), accessToken)));
                return;
            }

            if (req.getPathInfo().equals("/groups")) {
                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeActions(writer, accessToken, scope);
                writer.write("<h2>Groups response</h2>");
                JsonObject groups = makeGetRequest(new URL("https://graph.microsoft.com/v1.0/groups"), accessToken);
                writer.write(writeTextArea(groups));

                writer.write("<h3>Group list</h3>");
                groups.requiredArray("value").objects(o -> {
                    return "<li><a href='members?group=" + o.requiredString("id") + "&scope=" + scope + "&access_token=" + accessToken + "'>" + o.requiredString("displayName") + "</a></li>";
                }).forEach(writer::write);

                return;
            }

            if (req.getPathInfo().equals("/mygroups")) {
                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeActions(writer, accessToken, scope);
                writer.write("<h2>My groups response</h2>");
                writer.write(writeTextArea(makeGetRequest(new URL("https://graph.microsoft.com/v1.0/me/memberOf"), accessToken)));
                return;
            }

            if ("/oauth2callback".equals(req.getPathInfo())) {
                logger.info("Fetching access token to {}", tokenQuery(getRedirectUri(req), req.getParameter("code")));
                HttpURLConnection conn = postForm(new URL(getAuthority() + "/oauth2/v2.0/token"),
                        tokenQuery(getRedirectUri(req), req.getParameter("code")));

                JsonObject tokenResponse = JsonParser.parseToObject(conn);

                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeTokenResponse(writer, tokenResponse);
                writeActions(writer, tokenResponse.requiredString("access_token"), tokenResponse.requiredString("scope"));
                writer.write("</body>\n");
            }

        }

        private void writeActions(PrintWriter writer, String accessToken, String scope) {
            writer.write("<h2>Actions</h2>");
            writer.write("<p><a href='profile?scope=" + scope + "&access_token=" + accessToken + "'>Get profile with access token</a></p>");
            if (scope.contains("Group.Read.All")) {
                writer.write("<p><a href='mygroups?scope=" + scope + "&access_token=" + accessToken + "'>Show my groups</a></p>");
                writer.write("<p><a href='groups?scope=" + scope + "&access_token=" + accessToken + "'>List all groups</a></p>");
            }
            writer.write("<p><a href='/'>Front page</a></p>");
        }

        private String tokenQuery(String redirectUri, String code) {
            return "code=" + code + "&client_id=" + clientId + "&client_secret=" + clientSecret + "&redirect_uri="
                    + redirectUri + "&grant_type=authorization_code";
        }

        private String getAutheticationUrl(String redirectUri, String scope) {
            String authenticationQuery = "redirect_uri=" + redirectUri + "&response_type=code"
                    + "&scope=" + scope
                    + "&client_id=" + clientId;
            return getAuthority() + "/oauth2/v2.0/authorize" + "?" + authenticationQuery;
        }

        private String getAuthority() {
            return "https://login.microsoftonline.com/" + tenantId;
        }

        private String getRedirectUri(HttpServletRequest req) {
            return getBaseUrl(req) + req.getContextPath() + req.getServletPath() + "/oauth2callback";
        }

    }

    private static class EnterpriseActiveDirectoryServlet extends HttpServlet {
        private String tenantId;
        private String clientId;
        private String clientSecret;
        private String resource = "00000002-0000-0000-c000-000000000000";

        public EnterpriseActiveDirectoryServlet(String clientId, String clientSecret, String tenantId) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tenantId = tenantId;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            PrintWriter writer = resp.getWriter();
            if (req.getPathInfo().equals("/login")) {
                String autheticationUrl = getAutheticationUrl(getRedirectUri(req));
                String prompt = req.getParameter("prompt");
                if (prompt != null) {
                    autheticationUrl += "&prompt=" + prompt;
                }
                if (req.getParameter("domain_hint") != null) {
                    autheticationUrl += "&domain_hint=" + req.getParameter("domain_hint");
                }
                logger.info("Redirecting to {}", autheticationUrl);
                resp.sendRedirect(autheticationUrl);
                return;
            }

            String accessToken = req.getParameter("access_token");
            if (req.getPathInfo().equals("/profile")) {
                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeActions(writer, accessToken);
                writer.write("<h2>Profile response</h2>");
                writer.write(writeTextArea(makeGetRequest(new URL("https://graph.windows.net/me?api-version=1.6"), accessToken)));
                return;
            }

            if ("/oauth2callback".equals(req.getPathInfo())) {
                if (req.getParameter("error") != null) {
                    resp.setContentType("text/plain");
                    writer.write(req.getParameter("error") + "\n");
                    writer.write(req.getParameter("error_description") + "\n");
                    return;
                }
                logger.info("Fetching access token to {}", tokenQuery(getRedirectUri(req), req.getParameter("code")));
                HttpURLConnection conn = postForm(new URL(getAuthority() + "/oauth2/token"),
                        tokenQuery(getRedirectUri(req), req.getParameter("code")));
                JsonObject tokenResponse = JsonParser.parseToObject(conn);

                resp.setContentType("text/html");
                writer.write("<body>\n");
                writeTokenResponse(writer, tokenResponse);
                writeActions(writer, tokenResponse.requiredString("access_token"));
                writer.write("</body>\n");
            }

        }

        private void writeActions(PrintWriter writer, String accessToken) {
            writer.write("<h2>Actions</h2>");
            writer.write("<ul><li><a href='profile?access_token=" + accessToken + "'>Show profile</a></ul>");
            writer.write("<p><a href='/'>Front page</a></p>");
        }

        private String tokenQuery(String redirectUri, String code) {
            return "code=" + code + "&client_id=" + clientId + "&client_secret=" + clientSecret + "&redirect_uri="
                    + redirectUri + "&grant_type=authorization_code&resource=" + resource;
        }

        private String getAutheticationUrl(String redirectUri) {
            String authenticationQuery = "redirect_uri=" + redirectUri + "&response_type=code"
                    + "&client_id=" + clientId + "&resource=" + resource;
            return getAuthority() + "/oauth2/authorize" + "?" + authenticationQuery;
        }

        private String getAuthority() {
            return "https://login.microsoftonline.com/" + tenantId;
        }

        private String getRedirectUri(HttpServletRequest req) {
            return getBaseUrl(req) + req.getContextPath() + req.getServletPath() + "/oauth2callback";
        }
    }

    private class RootServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/html");
            PrintWriter writer = resp.getWriter();
            writer.append("<html><body>");
            writer.append("<h1>Welcome to the OAuth2 demo</h2>");
            if (getGoogleClientId() != null) {
                writer.append("<h2>Google authentication</h2>");
                writer.append("<p><a href='/google/login'>Log in</a></p>");
            } else if (req.getServerName().equals("localhost")) {
                writer.append("<h2>Google authentication</h2>");
                writer.append("<p>Register an app at <a href='https://console.cloud.google.com/apis/credentials'>Google developer console</a> to test out Google Authentication</p>");
            }
            if (getAdClientId() != null) {
                writer.append("<h2>Authentication with the <i>Microsoft</i> Graph API (new)</h2>");
                writer.append("<p><a href='/multiTenantActiveDirectory/login'>Log in</a></p>");
                writer.append("<p><a href='/multiTenantActiveDirectory/login?domain_hint=soprasteria.com'>Log in at soprasteria.com domain</a></p>");
                writer.append("<p><a href='/multiTenantActiveDirectory/login?prompt=admin_consent'>Log in as admin</a></p>" + "</body></html>");
            } else if (req.getServerName().equals("localhost")) {
                writer.append("<h2>Authentication with the <i>Microsoft</i> Graph API (new)</h2>");
                writer.append("<p>Register an app at <a href='https://apps.dev.microsoft.com/'>Microsoft App Registration Portal</a> to test out Microsoft Graph API</p>");
            }
            if (getEnterpriseClientId() != null) {
                writer.append("<h2>Multi-tenant app with <i>Windows</i> Graph API</h2>");
                writer.append("<p><a href='/enterprise/login'>Log in</a></p>");
                writer.append("<p><a href='/enterprise/login?domain_hint=soprasteria.com'>Log in at soprasteria.com domain</a></p>");
                writer.append("<p><a href='/enterprise/login?prompt=admin_consent'>Log in as admin</a></p>" + "</body></html>");
            }

            if (req.getParameter("debug") != null) {
                writer.append("<h3>HTTP debugging</h3>");
                writer.append("<ul>");
                for (String name : Collections.list(req.getHeaderNames())) {
                    writer.append("<li>" + name + " = " + req.getHeader(name) + "</li>");
                }
                writer.append("</ul>");
            }

            writer.append("</body></html>");
        }
    }

    private static String getBaseUrl(HttpServletRequest req) {
        String scheme = req.getHeader("x-forwarded-proto");
        if (scheme != null) {
            if (req.getHeader("x-forwarded-port") == null) {
                return scheme + "://" + req.getServerName();
            }
        } else {
            scheme = req.getScheme();
        }

        String port = Optional.ofNullable(req.getHeader("x-forwarded-port")).orElse(String.valueOf(req.getServerPort()));
        if (isDefaultPort(scheme, port)) {
            return scheme + "://" + req.getServerName();
        } else {
            return scheme + "://" + req.getServerName() + ":" + port;
        }
    }

    private static boolean isDefaultPort(String scheme, String port) {
        return (scheme.equals("http") && port.equals("80")) || scheme.equals("https") && port.equals("443");
    }

    public Application(String configFile) throws FileNotFoundException, IOException {
        try (FileReader reader = new FileReader(configFile)) {
            properties.load(reader);
        } catch (FileNotFoundException e) {
            logger.warn("File not found {}", new File(configFile).getAbsolutePath());
        }
    }

    public static void main(String[] args) throws Exception {
        new Application(System.getProperty("configFile", "application.properties")).startServer();
    }

    private void startServer() throws LifecycleException {
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(getPort());

        Context context = tomcat.addContext("", null);

        Tomcat.addServlet(context, "googleServlet", new GoogleAuthenticationServlet(getGoogleClientId(), getGoogleClientSecret()));
        context.addServletMappingDecoded("/google/*", "googleServlet");
        Tomcat.addServlet(context, "adMultiServlet", new MultiTenantActiveDirectoryServlet(getAdClientId(), getAdClientSecret(), "common"));
        context.addServletMappingDecoded("/multiTenantActiveDirectory/*", "adMultiServlet");
        Tomcat.addServlet(context, "enterpriseServlet", new EnterpriseActiveDirectoryServlet(getEnterpriseClientId(), getEnterpriseClientSecret(), "common"));
        context.addServletMappingDecoded("/enterprise/*", "enterpriseServlet");
        Tomcat.addServlet(context, "rootServlet", new RootServlet());
        context.addServletMappingDecoded("/*", "rootServlet");

        tomcat.start();
        tomcat.getServer().await();
    }

    private int getPort() {
        return Integer.parseInt(Optional.ofNullable(System.getenv("PORT"))
                .orElseGet(() -> System.getProperty("port.http", "9080")));
    }

    private int getEnv(String key, int defaultValue) {
        String value = System.getenv("key");
        return value != null ? Integer.parseInt(value) : defaultValue;
    }

    private String getProperty(String envKey, String propertyKey) {
        return Optional.ofNullable(System.getenv(envKey))
                .orElseGet(() -> properties.getProperty(propertyKey));
    }

    private String getEnterpriseTenant() {
        return getProperty("ENTERPRISE_TENANT", "enterprise.tenant");
    }

    private String getEnterpriseClientSecret() {
        return getProperty("ENTERPRISE_CLIENT_SECRET", "enterprise.client.secret");
    }


    private String getEnterpriseClientId() {
        return getProperty("ENTERPRISE_CLIENT_ID", "enterprise.client.id");
    }

    private String getAdClientSecret() {
        return getProperty("AD_CLIENT_SECRET", "ad.client.secret");
    }

    private String getAdClientId() {
        return getProperty("AD_CLIENT_ID", "ad.client.id");
    }

    private String getGoogleClientSecret() {
        return getProperty("GOOGLE_CLIENT_SECRET", "google.client.secret");
    }

    private String getGoogleClientId() {
        return getProperty("GOOGLE_CLIENT_ID", "google.client.id");
    }

    private static JsonObject makeGetRequest(URL url, String accessToken) throws IOException, MalformedURLException {
        URLConnection graphConn = url.openConnection();
        graphConn.setRequestProperty("Authorization", "Bearer " + accessToken);
        graphConn.setRequestProperty("Accept", "application/json");
        return JsonParser.parseToObject(graphConn);
    }

    private static HttpURLConnection postForm(URL url, String body) throws IOException, ProtocolException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        try (Writer wr = new OutputStreamWriter(conn.getOutputStream())) {
            wr.write(body);
        }
        return conn;
    }

    private static JsonObject parseIdTokenPayload(String idToken) {
        String[] parts = idToken.split("\\.");
        String header = parts[0], payload = parts[1], signature = parts.length > 2 ? parts[2] : null;

        return JsonParser.parseToObject(new String(Base64.getDecoder().decode(payload)));
    }

    private static void writeTokenResponse(PrintWriter writer, JsonObject tokenResponse) {
        writer.write("<h2>Token response</h2>");
        writer.write(writeTextArea(tokenResponse));

        JsonObject idToken = parseIdTokenPayload(tokenResponse.requiredString("id_token"));
        writer.write("<h2>ID TOKEN</h2>\n\n" + writeTextArea(idToken) + "\n\n");
        writer.write("<p><strong>Extracted name:</strong> " + idToken.stringValue("name").orElse("<missing>") + "</p>");
        String username = idToken.stringValue("preferred_username")
            .orElse(idToken.stringValue("unique_name")
                    .orElse(idToken.stringValue("email").orElse("<missing>")));
        writer.write("<p><strong>Extracted account:</strong> " + username + "</p>");
        writer.write("<p><strong>Extracted tenant:</strong> " + idToken.stringValue("tid").orElse("<missing>") + "</p>");
        writer.write("<p><strong>Extracted roles:</strong> " + idToken.arrayValue("roles").orElse(new JsonArray()) + "</p>");
    }

    private static String writeTextArea(JsonObject jsonObject) {
        return "<textarea cols='120' rows='20'>" + jsonObject.toIndentedJson("  ") + "</textarea>";
    }

}