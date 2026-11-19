package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class LdapTransportSubjectBuilderServiceConfigTest {

    @Test
    void acceptsAValidConfig() {
        assertThatNoException().isThrownBy(() -> new LdapTransportSubjectBuilderService.Config("CN", ldapConfig()));
    }

    @Test
    void rejectsBlankIdentityRdnType() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapTransportSubjectBuilderService.Config(" ", ldapConfig()));
    }

    @Test
    void rejectsNullIdentityRdnType() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapTransportSubjectBuilderService.Config(null, ldapConfig()));
    }

    @Test
    void rejectsNullLdapConfig() {
        assertThatNullPointerException().isThrownBy(() -> new LdapTransportSubjectBuilderService.Config("CN", null));
    }

    private static LdapRoleLookupConfig ldapConfig() {
        return new LdapRoleLookupConfig(
                List.of("ldap://directory.example.com:389"),
                "cn=kroxylicious,dc=example,dc=com",
                "secret",
                "ou=people,dc=example,dc=com",
                "(uid={0})",
                "memberOf",
                "cn=([^,]+),.*",
                OnLookupFailure.FAIL,
                Duration.ofSeconds(5),
                4,
                false,
                true,
                null);
    }
}
