package io.github.robobario.ldapprincipals;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RoleNameExtractorTest {

    @Test
    void extractsTheFirstCapturingGroup() {
        var extractor = new RoleNameExtractor("cn=([^,]+),.*");

        assertThat(extractor.extract("cn=kafka-admins,ou=groups,dc=example,dc=com")).contains("kafka-admins");
    }

    @Test
    void returnsEmptyWhenTheValueDoesNotMatch() {
        var extractor = new RoleNameExtractor("cn=([^,]+),.*");

        assertThat(extractor.extract("ou=people,dc=example,dc=com")).isEmpty();
    }

    @Test
    void matchingIsAnchoredToTheWholeValue() {
        var extractor = new RoleNameExtractor("cn=([^,]+)");

        assertThat(extractor.extract("cn=kafka-admins,ou=groups,dc=example,dc=com")).isEmpty();
    }

    @Test
    void usesOnlyTheFirstCapturingGroupWhenSeveralArePresent() {
        var extractor = new RoleNameExtractor("cn=([^,]+),ou=(.+)");

        assertThat(extractor.extract("cn=kafka-admins,ou=groups,dc=example,dc=com")).contains("kafka-admins");
    }

    @Test
    void returnsEmptyWhenTheFirstGroupMatchesButDoesNotCapture() {
        var extractor = new RoleNameExtractor("(cn=admins)?.*");

        assertThat(extractor.extract("ou=people,dc=example,dc=com")).isEmpty();
    }
}
