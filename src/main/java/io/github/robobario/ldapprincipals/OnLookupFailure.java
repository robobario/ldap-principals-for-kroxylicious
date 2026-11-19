package io.github.robobario.ldapprincipals;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Behavior when an LDAP role lookup fails (connection failure, timeout, malformed response).
 */
public enum OnLookupFailure {

    /** Fail {@code Subject} building, denying the connection. The safe default. */
    @JsonProperty("fail")
    FAIL,

    /**
     * Build a {@code Subject} carrying only the already-authenticated {@code User} principal, with no roles,
     * as if the lookup had found none.
     *
     * <p><strong>Privilege-escalation risk:</strong> only use this if your {@code Authorizer} treats
     * "no roles granted" as deny-by-default. If it instead treats "no roles claimed" as "no restriction
     * applies", an LDAP outage silently grants full access to every authenticated user.</p>
     */
    @JsonProperty("anonymous-roles")
    ANONYMOUS_ROLES
}
