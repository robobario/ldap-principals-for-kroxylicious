package io.github.robobario.ldapprincipals;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Maps a raw LDAP value (typically a group DN) to a role name, via a regex matched against the
 * whole value. Values that don't match the pattern yield no role, rather than leaking the raw
 * LDAP value through as a role name.
 */
final class RoleNameExtractor {

    private final Pattern pattern;

    RoleNameExtractor(String regex) {
        this.pattern = Pattern.compile(regex);
    }

    Optional<String> extract(String rawValue) {
        var matcher = pattern.matcher(rawValue);
        if (!matcher.matches()) {
            return Optional.empty();
        }
        return Optional.ofNullable(matcher.group(1));
    }
}
