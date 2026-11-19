package io.github.robobario.ldapprincipals;

import java.util.List;

/** Looks up the raw role/group values held for an identity. Implementations run synchronously and may block. */
interface RoleLookup {

    List<String> lookupRoles(String identity);
}
