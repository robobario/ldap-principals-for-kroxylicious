package io.github.robobario.ldapprincipals;

import java.net.URI;

/**
 * A single LDAP server endpoint and its transport security settings.
 *
 * @param uri LDAP server URI, {@code ldap://host:port} or {@code ldaps://host:port}.
 * @param startTls upgrade an {@code ldap://} connection to TLS via the StartTLS extended operation.
 *        Not valid with an {@code ldaps://} URI, which already establishes TLS.
 * @param trustStore truststore validating this server's certificate, e.g. for a private CA. {@code null}
 *        uses the JVM's default truststore. Applies only to {@code ldaps://} or StartTLS connections.
 */
public record LdapServerConfig(String uri, boolean startTls, LdapTrustStoreConfig trustStore) {

    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;

    public LdapServerConfig {
        URI parsed = parse(uri);
        String scheme = parsed.getScheme();
        if ("ldaps".equals(scheme)) {
            if (startTls) {
                throw new IllegalArgumentException(
                        "startTls cannot be used with 'ldaps://' server URI '" + uri + "': ldaps:// already establishes TLS");
            }
        }
        else if (!"ldap".equals(scheme)) {
            throw new IllegalArgumentException(
                    "Unsupported scheme in server URI '" + uri + "': only 'ldap://' and 'ldaps://' are supported");
        }
        if (parsed.getHost() == null) {
            throw new IllegalArgumentException("Server URI '" + uri + "' is missing a host");
        }
    }

    boolean useSsl() {
        return "ldaps".equals(parse(uri).getScheme());
    }

    boolean isPlaintext() {
        return !useSsl() && !startTls;
    }

    String host() {
        return parse(uri).getHost();
    }

    int port() {
        int port = parse(uri).getPort();
        return port != -1 ? port : useSsl() ? DEFAULT_LDAPS_PORT : DEFAULT_LDAP_PORT;
    }

    private static URI parse(String uri) {
        try {
            return URI.create(uri);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid LDAP server URI '" + uri + "'", e);
        }
    }
}
