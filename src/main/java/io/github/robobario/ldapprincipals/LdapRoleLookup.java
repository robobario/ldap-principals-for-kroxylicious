package io.github.robobario.ldapprincipals;

import java.io.IOException;
import java.net.URI;
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

/**
 * Looks up the raw {@code memberOf} values of an identity against a directory, trying each
 * configured server URI in turn. Returns raw LDAP values (typically group DNs); mapping them
 * to role names is the caller's responsibility.
 */
final class LdapRoleLookup implements RoleLookup {

    private final List<String> serverUris;
    private final String bindDn;
    private final String bindPassword;
    private final String searchBase;
    private final String searchFilterTemplate;
    private final String memberOfAttribute;
    private final long timeoutMillis;
    private final boolean startTls;
    private final TrustManager[] trustManagers;

    LdapRoleLookup(LdapRoleLookupConfig config) {
        this.serverUris = config.serverUris();
        this.bindDn = config.bindDn();
        this.bindPassword = config.bindPassword();
        this.searchBase = config.searchBase();
        this.searchFilterTemplate = config.searchFilterTemplate();
        this.memberOfAttribute = config.memberOfAttribute();
        this.timeoutMillis = config.lookupTimeout().toMillis();
        this.startTls = config.startTls();
        this.trustManagers = config.trustStore() == null ? null : config.trustStore().toTrustManagers();
    }

    @Override
    public List<String> lookupRoles(String identity) {
        Exception lastFailure = null;
        for (String serverUri : serverUris) {
            try {
                return lookupRoles(serverUri, identity);
            }
            catch (LdapException | CursorException | IOException e) {
                lastFailure = e;
            }
        }
        throw new LdapRoleLookupException(
                "Unable to look up roles for identity '" + identity + "': no configured LDAP server could be reached", lastFailure);
    }

    private List<String> lookupRoles(String serverUri, String identity) throws LdapException, CursorException, IOException {
        URI uri = URI.create(serverUri);
        boolean useSsl = "ldaps".equals(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : useSsl ? 636 : 389;
        LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
        connectionConfig.setLdapHost(uri.getHost());
        connectionConfig.setLdapPort(port);
        connectionConfig.setTimeout(timeoutMillis);
        connectionConfig.setUseSsl(useSsl);
        connectionConfig.setUseTls(startTls);
        connectionConfig.setSslEndpointIdentificationAlgorithm("LDAPS");
        if (trustManagers != null) {
            connectionConfig.setTrustManagers(trustManagers);
        }
        try (LdapNetworkConnection connection = new LdapNetworkConnection(connectionConfig)) {
            connection.bind(bindDn, bindPassword);
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
}
