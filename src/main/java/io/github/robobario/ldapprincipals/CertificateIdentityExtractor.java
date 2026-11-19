package io.github.robobario.ldapprincipals;

import java.util.Optional;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

/**
 * Extracts an identity from a certificate subject DN by selecting a named RDN (e.g. {@code CN}).
 * Parses the DN per RFC 2253 so escaped separators and non-leading RDNs are handled correctly.
 */
final class CertificateIdentityExtractor {

    private final String rdnType;

    CertificateIdentityExtractor(String rdnType) {
        this.rdnType = rdnType;
    }

    String rdnType() {
        return rdnType;
    }

    Optional<String> extract(String subjectDn) {
        LdapName name;
        try {
            name = new LdapName(subjectDn);
        }
        catch (InvalidNameException e) {
            return Optional.empty();
        }
        return name.getRdns().stream()
                .filter(rdn -> rdn.getType().equalsIgnoreCase(rdnType))
                .map(rdn -> rdn.getValue().toString())
                .findFirst();
    }

    static void validateRdnType(String rdnType, String fieldName) {
        if (rdnType == null || rdnType.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
