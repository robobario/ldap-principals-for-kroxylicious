package io.github.robobario.ldapprincipals;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Shared LDAP connectivity and role-lookup configuration, used by both {@link LdapSaslSubjectBuilderService}
 * and {@link LdapTransportSubjectBuilderService}.
 *
 * @param serverUris LDAP server URIs ({@code ldap://host:port}), tried in order until one succeeds.
 * @param bindDn DN of the service account used to query LDAP.
 * @param bindPassword password of the service account. Supplied inline; file-based secret sources are not yet supported.
 * @param searchBase base DN under which the identity's entry is searched for.
 * @param searchFilterTemplate search filter containing a {@code {0}} placeholder for the identity,
 *        e.g. {@code (uid={0})}. The identity is escaped before substitution.
 * @param memberOfAttribute name of the multi-valued attribute holding group membership. Defaults to {@code memberOf}.
 * @param roleNameExtractionPattern regex matched against each raw LDAP value (typically a group DN) to derive a role
 *        name, e.g. {@code cn=([^,]+),.*}. Must contain at least one capturing group; values that don't match the
 *        pattern contribute no role.
 * @param onLookupFailure behavior on LDAP lookup failure (connection failure, timeout, malformed response).
 *        Defaults to {@link OnLookupFailure#FAIL}. See {@link OnLookupFailure#ANONYMOUS_ROLES} for the
 *        privilege-escalation risk of the permissive option.
 * @param lookupTimeout maximum time to wait for a lookup to complete.
 * @param executorPoolSize size of the dedicated executor LDAP operations run on.
 */
public record LdapRoleLookupConfig(
        List<String> serverUris,
        String bindDn,
        String bindPassword,
        String searchBase,
        String searchFilterTemplate,
        String memberOfAttribute,
        String roleNameExtractionPattern,
        OnLookupFailure onLookupFailure,
        Duration lookupTimeout,
        int executorPoolSize) {

    static final String IDENTITY_PLACEHOLDER = "{0}";
    private static final String DEFAULT_MEMBER_OF_ATTRIBUTE = "memberOf";

    public LdapRoleLookupConfig {
        if (serverUris == null || serverUris.isEmpty()) {
            throw new IllegalArgumentException("serverUris must not be empty");
        }
        serverUris = List.copyOf(serverUris);
        serverUris.forEach(LdapRoleLookupConfig::validateServerUri);
        requireNonBlank(bindDn, "bindDn");
        Objects.requireNonNull(bindPassword, "bindPassword must not be null");
        requireNonBlank(searchBase, "searchBase");
        requireNonBlank(searchFilterTemplate, "searchFilterTemplate");
        if (!searchFilterTemplate.contains(IDENTITY_PLACEHOLDER)) {
            throw new IllegalArgumentException(
                    "searchFilterTemplate must contain the '" + IDENTITY_PLACEHOLDER + "' placeholder");
        }
        memberOfAttribute = memberOfAttribute == null || memberOfAttribute.isBlank() ? DEFAULT_MEMBER_OF_ATTRIBUTE : memberOfAttribute;
        RoleNameExtractor.validatePattern(roleNameExtractionPattern, "roleNameExtractionPattern");
        onLookupFailure = onLookupFailure == null ? OnLookupFailure.FAIL : onLookupFailure;
        Objects.requireNonNull(lookupTimeout, "lookupTimeout must not be null");
        if (!lookupTimeout.isPositive()) {
            throw new IllegalArgumentException("lookupTimeout must be positive");
        }
        if (executorPoolSize < 1) {
            throw new IllegalArgumentException("executorPoolSize must be at least 1");
        }
    }

    private static void validateServerUri(String serverUri) {
        URI uri;
        try {
            uri = URI.create(serverUri);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid LDAP server URI '" + serverUri + "'", e);
        }
        if (!"ldap".equals(uri.getScheme())) {
            throw new IllegalArgumentException(
                    "Unsupported scheme in server URI '" + serverUri + "': only 'ldap://' is supported until TLS support is added");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Server URI '" + serverUri + "' is missing a host");
        }
    }

    private static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }

    @Override
    public String toString() {
        return "LdapRoleLookupConfig[serverUris=" + serverUris + ", bindDn=" + bindDn + ", bindPassword=***, searchBase=" + searchBase
                + ", searchFilterTemplate=" + searchFilterTemplate + ", memberOfAttribute=" + memberOfAttribute
                + ", roleNameExtractionPattern=" + roleNameExtractionPattern + ", onLookupFailure=" + onLookupFailure
                + ", lookupTimeout=" + lookupTimeout + ", executorPoolSize=" + executorPoolSize + "]";
    }
}
