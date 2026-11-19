package io.github.robobario.ldapprincipals;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Shared LDAP connectivity and role-lookup configuration, used by both {@link LdapSaslSubjectBuilderService}
 * and {@link LdapTransportSubjectBuilderService}.
 *
 * @param serverUris LDAP server URIs ({@code ldap://host:port} or {@code ldaps://host:port}), tried in order
 *        until one succeeds.
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
 * @param startTls upgrade an {@code ldap://} connection to TLS via the StartTLS extended operation. Not valid
 *        together with an {@code ldaps://} server URI, which is already TLS.
 * @param allowPlaintextLdap explicit opt-in to connect to an {@code ldap://} server URI without {@code startTls}.
 *        Without this flag, a plaintext {@code ldap://} server URI is rejected at config-load time.
 * @param trustStore truststore used to validate the LDAP server's certificate, e.g. for a private CA. {@code null}
 *        to use the JVM's default truststore. Ignored when every server URI is plaintext {@code ldap://}.
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
        int executorPoolSize,
        boolean startTls,
        boolean allowPlaintextLdap,
        LdapTrustStoreConfig trustStore) {

    static final String IDENTITY_PLACEHOLDER = "{0}";
    private static final String DEFAULT_MEMBER_OF_ATTRIBUTE = "memberOf";

    public LdapRoleLookupConfig {
        if (serverUris == null || serverUris.isEmpty()) {
            throw new IllegalArgumentException("serverUris must not be empty");
        }
        serverUris = List.copyOf(serverUris);
        serverUris.forEach(uri -> validateServerUri(uri, startTls, allowPlaintextLdap));
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

    private static void validateServerUri(String serverUri, boolean startTls, boolean allowPlaintextLdap) {
        URI uri;
        try {
            uri = URI.create(serverUri);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid LDAP server URI '" + serverUri + "'", e);
        }
        String scheme = uri.getScheme();
        if ("ldaps".equals(scheme)) {
            if (startTls) {
                throw new IllegalArgumentException(
                        "startTls cannot be used with 'ldaps://' server URI '" + serverUri + "': ldaps:// already establishes TLS");
            }
        }
        else if ("ldap".equals(scheme)) {
            if (!startTls && !allowPlaintextLdap) {
                throw new IllegalArgumentException(
                        "Plaintext server URI '" + serverUri + "' requires either startTls or allowPlaintextLdap to be set");
            }
        }
        else {
            throw new IllegalArgumentException(
                    "Unsupported scheme in server URI '" + serverUri + "': only 'ldap://' and 'ldaps://' are supported");
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
                + ", lookupTimeout=" + lookupTimeout + ", executorPoolSize=" + executorPoolSize + ", startTls=" + startTls
                + ", allowPlaintextLdap=" + allowPlaintextLdap + ", trustStore=" + trustStore + "]";
    }
}
