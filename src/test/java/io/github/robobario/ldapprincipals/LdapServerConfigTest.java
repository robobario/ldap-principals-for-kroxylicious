package io.github.robobario.ldapprincipals;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class LdapServerConfigTest {

    @Test
    void rejectsUnsupportedScheme() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapServerConfig("http://directory.example.com:389", false, null));
    }

    @Test
    void rejectsUriWithoutHost() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapServerConfig("ldap:///", false, null));
    }

    @Test
    void rejectsStartTlsWithLdapsScheme() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapServerConfig("ldaps://directory.example.com:636", true, null));
    }

    @Test
    void acceptsPlaintextLdap() {
        assertThatNoException().isThrownBy(() -> new LdapServerConfig("ldap://directory.example.com:389", false, null));
    }

    @Test
    void acceptsStartTls() {
        assertThatNoException().isThrownBy(() -> new LdapServerConfig("ldap://directory.example.com:389", true, null));
    }

    @Test
    void acceptsLdaps() {
        assertThatNoException().isThrownBy(() -> new LdapServerConfig("ldaps://directory.example.com:636", false, null));
    }

    @Test
    void plaintextLdapWithoutStartTlsIsPlaintext() {
        assertThat(new LdapServerConfig("ldap://host:389", false, null).isPlaintext()).isTrue();
    }

    @Test
    void startTlsIsNotPlaintext() {
        assertThat(new LdapServerConfig("ldap://host:389", true, null).isPlaintext()).isFalse();
    }

    @Test
    void ldapsIsNotPlaintext() {
        assertThat(new LdapServerConfig("ldaps://host:636", false, null).isPlaintext()).isFalse();
    }

    @Test
    void defaultsLdapPortWhenAbsent() {
        assertThat(new LdapServerConfig("ldap://host", false, null).port()).isEqualTo(389);
    }

    @Test
    void defaultsLdapsPortWhenAbsent() {
        assertThat(new LdapServerConfig("ldaps://host", false, null).port()).isEqualTo(636);
    }

    @Test
    void usesExplicitPort() {
        assertThat(new LdapServerConfig("ldap://host:1234", false, null).port()).isEqualTo(1234);
    }
}
