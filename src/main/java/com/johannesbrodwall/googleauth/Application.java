package com.johannesbrodwall.googleauth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;

public class Application {

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

            if ("/oauth2/callback".equals(req.getPathInfo())) {
                HttpURLConnection conn = postForm(new URL("https://accounts.google.com/o/oauth2/token"),
                        tokenQuery(getRedirectUri(req), req.getParameter("code")));

                if (conn.getResponseCode() < 400) {
                    resp.getWriter().write("Token response\n\n");
                    JsonObject tokenResponse = JsonParser.parseToObject(conn.getInputStream());
                    resp.getWriter().write(tokenResponse.toString());

                    JsonObject idToken = parseIdTokenPayload(tokenResponse.requiredString("id_token"));
                    resp.getWriter().write("\n\nID TOKEN\n\n" + idToken + "\n\n");

                    String accessToken = tokenResponse.requiredString("access_token");
                    JsonObject jsonProfile = getProfile(accessToken);

                    resp.getWriter().write("\n\nPROFILE\n\n" + jsonProfile);
                } else {
                    resp.getWriter().write("Uh oh! " + JsonParser.parseToObject(conn.getErrorStream()));
                }
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
            URL tokenUrl = new URL("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + accessToken);
            try (InputStream input = tokenUrl.openStream()) {
                return JsonParser.parseToObject(input);
            }
        }

        private String tokenQuery(String redirectUri, String code) {
            return "code=" + code
                    + "&client_id=" + clientId + "&client_secret=" + clientSecret +
                    "&redirect_uri=" + redirectUri + "&grant_type=authorization_code";
        }

        private String getRedirectUri(HttpServletRequest req) {
            return req.getScheme() + "://" + req.getServerName() + ":" + req.getLocalPort()
                + req.getContextPath() + req.getServletPath() + "/oauth2/callback";
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
            if (req.getPathInfo().equals("/")) {
                resp.setContentType("text/html");
                resp.getWriter().append("<html><body>" + "<p><a href='login'>Log in</a></p>"
                        + "<p><a href='login?domain_hint=soprasteria.com'>Log in at soprasteria.com domain</a></p>"
                        + "<p><a href='login?prompt=admin_consent'>Log in as admin</a></p>" + "</body></html>");
                return;
            }

            if (req.getPathInfo().equals("/login")) {
                String autheticationUrl = getAutheticationUrl(getRedirectUri(req));
                if (req.getParameter("domain_hint") != null) {
                    autheticationUrl += "&domain_hint=" + req.getParameter("domain_hint");
                }
                if (req.getParameter("prompt") != null) {
                    autheticationUrl += "&prompt=" + req.getParameter("prompt");
                }
                resp.sendRedirect(autheticationUrl);
                return;
            }

            if ("/oauth2/callback".equals(req.getPathInfo())) {
                HttpURLConnection conn = postForm(new URL("https://login.microsoft.com/common/oauth2/token"),
                        tokenQuery(getRedirectUri(req), req.getParameter("code")));

                if (conn.getResponseCode() < 400) {
                    JsonObject tokenResponse = JsonParser.parseToObject(conn.getInputStream());
                    resp.getWriter().write("Token response\n\n");
                    resp.getWriter().write(tokenResponse.toString());

                    JsonObject idToken = parseIdTokenPayload(tokenResponse.requiredString("id_token"));
                    resp.getWriter().write("\n\nID TOKEN\n\n" + idToken + "\n\n");

                    String accessToken = tokenResponse.requiredString("access_token");

                    resp.getWriter().write("\n\n");
                    resp.getWriter().write(getProfile(accessToken));
                } else {
                    resp.getWriter().write("Uh oh " + JsonParser.parse(conn.getErrorStream()));
                }
            }

        }

        private String getProfile(String accessToken) throws IOException, MalformedURLException {
            HttpURLConnection graphConn = (HttpURLConnection) new URL("https://graph.microsoft.com/v1.0/me/")
                    .openConnection();
            graphConn.setRequestProperty("Authorization", "Bearer " + accessToken);

            if (graphConn.getResponseCode() < 400) {
                return JsonParser.parseToObject(graphConn.getInputStream()).toString();
            } else {
                String body = graphConn.getResponseMessage() + "\n";
                try (BufferedReader reader = new BufferedReader( new InputStreamReader(graphConn.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        body += line;
                    }
                }
                return body;
            }
        }

        private String tokenQuery(String redirectUri, String code) {
            return "code=" + code + "&client_id=" + clientId + "&client_secret=" + clientSecret + "&redirect_uri="
                    + redirectUri + "&grant_type=authorization_code" + "&resource=831c1487-a6e9-4b73-953e-2ffb15450993";
        }

        private String getAutheticationUrl(String redirectUri) {
            String authenticationQuery = "redirect_uri=" + redirectUri + "&response_type=code"
                    + "&scopes=Group.Read.All+User.Read+openid"
                    // + "&login_hint=johannes.brodwall@soprasteria.com"
                    + "&client_id=" + clientId;
            return getAuthority() + "?" + authenticationQuery;
        }

        private String getAuthority() {
            return "https://login.microsoft.com/" + tenantId + "/oauth2/authorize";
        }

        private String getRedirectUri(HttpServletRequest req) {
            return req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort() + req.getContextPath() + req.getServletPath() + "/oauth2/callback";
        }
    }

    private static class RootServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/html");
            resp.getWriter().append("<html><body>"
                    + "<h2>Google authentication</h2>"
                    + "<p><a href='/google/login'>Log in</a></p>"
                    + "<h2>Multi-tenant Active Directory</h2>"
                    + "<p><a href='/multiTenantActiveDirectory/login'>Log in</a></p>"
                    + "<p><a href='/multiTenantActiveDirectory/login?domain_hint=soprasteria.com'>Log in at soprasteria.com domain</a></p>"
                    + "<p><a href='/multiTenantActiveDirectory/login?prompt=admin_consent'>Log in as admin</a></p>" + "</body></html>"
                    + "<h2>Active Directory</h2>"
                    + "<p><a href='/activeDirectory/login'>Log in</a></p>"
                    + "</body></html>");
        }
    }

    public static void main(String[] args) throws Exception {
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(9080);
        tomcat.start();

        Context context = tomcat.addContext("", null);

        Tomcat.addServlet(context, "googleServlet", new GoogleAuthenticationServlet(getGoogleClientId(), getGoogleClientSecret()));
        context.addServletMappingDecoded("/google/*", "googleServlet");
        Tomcat.addServlet(context, "adMultiServlet", new MultiTenantActiveDirectoryServlet(getAdClientId(), getAdClientSecret(), "common"));
        context.addServletMappingDecoded("/multiTenantActiveDirectory/*", "adMultiServlet");
//        Tomcat.addServlet(context, "adServlet", new MultiTenantActiveDirectoryServlet("78a643e0-2a8e-47ed-a395-4be40e05a2ad", , "b1656b00-ea0b-4ff5-aac7-8fb45323833d"));
//        context.addServletMappingDecoded("/activeDirectory/*", "adServlet");
        Tomcat.addServlet(context, "rootServlet", new RootServlet());
        context.addServletMappingDecoded("/*", "rootServlet");

        tomcat.getServer().await();
    }

    private static String getAdClientSecret() {
        return System.getenv("AD_CLIENT_SECRET");
    }

    private static String getAdClientId() {
        return "831c1487-a6e9-4b73-953e-2ffb15450993";
    }

    private static String getGoogleClientSecret() {
        return System.getenv("GOOGLE_CLIENT_SECRET");
    }

    private static String getGoogleClientId() {
        return "1074484419690-00tnaj9c1l121c166e4h66spshguspu1.apps.googleusercontent.com";
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

}
