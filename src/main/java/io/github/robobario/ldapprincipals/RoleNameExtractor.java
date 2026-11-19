package io.github.robobario.ldapprincipals;

import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Maps a raw value to a name, via a regex matched against the whole value. Values that don't
 * match the pattern yield no result, rather than leaking the raw value through unmapped.
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

    /**
     * Validates that {@code regex} is non-blank, a valid regex, and has at least one capturing group.
     *
     * @param fieldName name to use for {@code regex} in exception messages.
     */
    static void validatePattern(String regex, String fieldName) {
        if (regex == null || regex.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        Pattern compiled;
        try {
            compiled = Pattern.compile(regex);
        }
        catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid " + fieldName + " '" + regex + "'", e);
        }
        if (compiled.matcher("").groupCount() < 1) {
            throw new IllegalArgumentException(fieldName + " '" + regex + "' must contain at least one capturing group");
        }
    }
}
