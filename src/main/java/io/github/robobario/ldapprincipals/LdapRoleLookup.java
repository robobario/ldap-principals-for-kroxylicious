package io.github.robobario.ldapprincipals;

import java.security.GeneralSecurityException;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.SSLUtil;

import io.kroxylicious.proxy.config.secret.PasswordProvider;

/**
 * Looks up the raw {@code memberOf} values of an identity against a directory, trying each
 * configured server URI in turn. Returns raw LDAP values (typically group DNs); mapping them
 * to role names is the caller's responsibility.
 */
final class LdapRoleLookup implements RoleLookup {

    private final List<Server> servers;
    private final String bindDn;
    private final PasswordProvider bindPassword;
    private final String searchBase;
    private final String searchFilterTemplate;
    private final String memberOfAttribute;
    private final long timeoutMillis;

    LdapRoleLookup(LdapRoleLookupConfig config) {
        this.servers = config.servers().stream().map(Server::from).toList();
        this.bindDn = config.bindDn();
        this.bindPassword = config.bindPassword();
        this.searchBase = config.searchBase();
        this.searchFilterTemplate = config.searchFilterTemplate();
        this.memberOfAttribute = config.memberOfAttribute();
        this.timeoutMillis = config.lookupTimeout().toMillis();
    }

    @Override
    public List<String> lookupRoles(String identity) {
        Exception lastFailure = null;
        for (Server server : servers) {
            try {
                return lookupRoles(server, identity);
            }
            catch (LDAPException | GeneralSecurityException e) {
                lastFailure = e;
            }
        }
        throw new LdapRoleLookupException(
                "Unable to look up roles for identity '" + identity + "': no configured LDAP server could be reached", lastFailure);
    }

    private List<String> lookupRoles(Server server, String identity) throws LDAPException, GeneralSecurityException {
        LDAPConnectionOptions options = new LDAPConnectionOptions();
        options.setConnectTimeoutMillis((int) Math.min(timeoutMillis, Integer.MAX_VALUE));
        options.setResponseTimeoutMillis(timeoutMillis);

        SocketFactory socketFactory = null;
        if (server.useSsl()) {
            options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
            socketFactory = new SSLUtil(server.trustManagers()).createSSLSocketFactory();
        }

        try (LDAPConnection connection = socketFactory == null
                ? new LDAPConnection(options, server.host(), server.port())
                : new LDAPConnection(socketFactory, options, server.host(), server.port())) {

            if (server.startTls()) {
                SSLContext sslContext = new SSLUtil(server.trustManagers()).createSSLContext();
                connection.processExtendedOperation(new StartTLSExtendedRequest(sslContext));
            }
            connection.bind(bindDn, bindPassword.getProvidedPassword());

            String filter = searchFilterTemplate.replace(
                    LdapRoleLookupConfig.IDENTITY_PLACEHOLDER, Filter.encodeValue(identity));
            SearchResult result = connection.search(searchBase, SearchScope.SUB, filter, memberOfAttribute);

            List<SearchResultEntry> entries = result.getSearchEntries();
            if (entries.isEmpty()) {
                return List.of();
            }
            if (entries.size() > 1) {
                throw new LdapRoleLookupException(
                        "Search filter matched more than one entry for identity '" + identity + "'", null);
            }
            Attribute attribute = entries.get(0).getAttribute(memberOfAttribute);
            return attribute == null ? List.of() : List.of(attribute.getValues());
        }
    }

    private record Server(String host, int port, boolean useSsl, boolean startTls, TrustManager[] trustManagers) {
        static Server from(LdapServerConfig config) {
            return new Server(config.host(), config.port(), config.useSsl(), config.startTls(),
                    config.trustStore() == null ? null : config.trustStore().toTrustManagers());
        }
    }
}
