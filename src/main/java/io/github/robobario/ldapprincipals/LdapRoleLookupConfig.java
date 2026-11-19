package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Shared LDAP connectivity and role-lookup configuration, used by both {@link LdapSaslSubjectBuilderService}
 * and {@link LdapTransportSubjectBuilderService}.
 *
 * @param servers LDAP servers, tried in order until one succeeds. Each carries its own URI and TLS settings.
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
 * @param allowPlaintextLdap global opt-in to connect to any {@code ldap://} server without {@code startTls}.
 *        Without this flag, a plaintext server is rejected at config-load time.
 */
public record LdapRoleLookupConfig(
        List<LdapServerConfig> servers,
        String bindDn,
        String bindPassword,
        String searchBase,
        String searchFilterTemplate,
        String memberOfAttribute,
        String roleNameExtractionPattern,
        OnLookupFailure onLookupFailure,
        Duration lookupTimeout,
        int executorPoolSize,
        boolean allowPlaintextLdap) {

    static final String IDENTITY_PLACEHOLDER = "{0}";
    private static final String DEFAULT_MEMBER_OF_ATTRIBUTE = "memberOf";

    public LdapRoleLookupConfig {
        if (servers == null || servers.isEmpty()) {
            throw new IllegalArgumentException("servers must not be empty");
        }
        servers = List.copyOf(servers);
        servers.forEach(server -> {
            if (server.isPlaintext() && !allowPlaintextLdap) {
                throw new IllegalArgumentException(
                        "Plaintext server URI '" + server.uri() + "' requires either startTls or allowPlaintextLdap to be set");
            }
        });
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

    private static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }

    @Override
    public String toString() {
        return "LdapRoleLookupConfig[servers=" + servers + ", bindDn=" + bindDn + ", bindPassword=***, searchBase=" + searchBase
                + ", searchFilterTemplate=" + searchFilterTemplate + ", memberOfAttribute=" + memberOfAttribute
                + ", roleNameExtractionPattern=" + roleNameExtractionPattern + ", onLookupFailure=" + onLookupFailure
                + ", lookupTimeout=" + lookupTimeout + ", executorPoolSize=" + executorPoolSize
                + ", allowPlaintextLdap=" + allowPlaintextLdap + "]";
    }
}
