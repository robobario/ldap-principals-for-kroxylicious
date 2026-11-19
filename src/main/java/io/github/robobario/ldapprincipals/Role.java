package io.github.robobario.ldapprincipals;

import io.kroxylicious.proxy.authentication.Principal;

/**
 * A role/group membership principal, derived from an LDAP lookup. Not {@code @Unique}:
 * a {@code Subject} may carry zero or more roles alongside its single {@code User}.
 *
 * @param name the role name.
 */
public record Role(String name) implements Principal {}
