package io.github.robobario.ldapprincipals;

/** Thrown when an LDAP role lookup cannot be completed against any configured server. */
final class LdapRoleLookupException extends RuntimeException {

    LdapRoleLookupException(String message, Throwable cause) {
        super(message, cause);
    }
}
