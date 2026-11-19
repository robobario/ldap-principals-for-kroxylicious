package io.github.robobario.ldapprincipals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManager;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

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
            catch (LdapException | CursorException | IOException e) {
                lastFailure = e;
            }
        }
        throw new LdapRoleLookupException(
                "Unable to look up roles for identity '" + identity + "': no configured LDAP server could be reached", lastFailure);
    }

    private List<String> lookupRoles(Server server, String identity) throws LdapException, CursorException, IOException {
        LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
        connectionConfig.setLdapHost(server.host());
        connectionConfig.setLdapPort(server.port());
        connectionConfig.setTimeout(timeoutMillis);
        connectionConfig.setUseSsl(server.useSsl());
        connectionConfig.setUseTls(server.startTls());
        connectionConfig.setSslEndpointIdentificationAlgorithm("LDAPS");
        if (server.trustManagers() != null) {
            connectionConfig.setTrustManagers(server.trustManagers());
        }
        try (LdapNetworkConnection connection = new LdapNetworkConnection(connectionConfig)) {
            connection.bind(bindDn, bindPassword.getProvidedPassword());
            String filter = searchFilterTemplate.replace(
                    LdapRoleLookupConfig.IDENTITY_PLACEHOLDER, FilterEncoder.encodeFilterValue(identity));
            try (EntryCursor cursor = connection.search(searchBase, filter, SearchScope.SUBTREE, memberOfAttribute)) {
                if (!cursor.next()) {
                    return List.of();
                }
                Entry entry = cursor.get();
                if (cursor.next()) {
                    throw new LdapRoleLookupException(
                            "Search filter matched more than one entry for identity '" + identity + "'", null);
                }
                Attribute attribute = entry.get(memberOfAttribute);
                if (attribute == null) {
                    return List.of();
                }
                List<String> roles = new ArrayList<>();
                for (Value value : attribute) {
                    roles.add(value.getString());
                }
                return roles;
            }
        }
    }

    private record Server(String host, int port, boolean useSsl, boolean startTls, TrustManager[] trustManagers) {
        static Server from(LdapServerConfig config) {
            return new Server(config.host(), config.port(), config.useSsl(), config.startTls(),
                    config.trustStore() == null ? null : config.trustStore().toTrustManagers());
        }
    }
}
