package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class LdapRoleLookupConfigTest {

    @Test
    void acceptsAValidConfig() {
        assertThatNoException().isThrownBy(() -> validConfig().build());
    }

    @Test
    void rejectsEmptyServerUris() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().serverUris(List.of()).build());
    }

    @Test
    void rejectsNonLdapScheme() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().serverUris(List.of("ldaps://directory.example.com:636")).build());
    }

    @Test
    void rejectsServerUriWithoutHost() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().serverUris(List.of("ldap:///")).build());
    }

    @Test
    void rejectsBlankBindDn() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().bindDn(" ").build());
    }

    @Test
    void rejectsBlankSearchBase() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().searchBase(" ").build());
    }

    @Test
    void rejectsSearchFilterTemplateMissingThePlaceholder() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().searchFilterTemplate("(uid=alice)").build());
    }

    @Test
    void rejectsBlankRoleNameExtractionPattern() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().roleNameExtractionPattern(" ").build());
    }

    @Test
    void rejectsInvalidRoleNameExtractionPattern() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().roleNameExtractionPattern("cn=(([^,]+,.*").build());
    }

    @Test
    void rejectsRoleNameExtractionPatternWithoutACapturingGroup() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().roleNameExtractionPattern("cn=[^,]+,.*").build());
    }

    @Test
    void defaultsBlankMemberOfAttributeToMemberOf() {
        var config = validConfig().memberOfAttribute(" ").build();

        assertThat(config.memberOfAttribute()).isEqualTo("memberOf");
    }

    @Test
    void defaultsNullOnLookupFailureToFail() {
        var config = validConfig().onLookupFailure(null).build();

        assertThat(config.onLookupFailure()).isEqualTo(OnLookupFailure.FAIL);
    }

    @Test
    void acceptsAnonymousRolesOnLookupFailure() {
        var config = validConfig().onLookupFailure(OnLookupFailure.ANONYMOUS_ROLES).build();

        assertThat(config.onLookupFailure()).isEqualTo(OnLookupFailure.ANONYMOUS_ROLES);
    }

    @Test
    void rejectsNonPositiveLookupTimeout() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().lookupTimeout(Duration.ZERO).build());
    }

    @Test
    void rejectsNonPositiveExecutorPoolSize() {
        assertThatIllegalArgumentException().isThrownBy(() -> validConfig().executorPoolSize(0).build());
    }

    @Test
    void toStringDoesNotLeakBindPassword() {
        var config = new ConfigBuilder();
        config.bindPassword = "super-secret";

        assertThat(config.build().toString()).doesNotContain("super-secret");
    }

    private static ConfigBuilder validConfig() {
        return new ConfigBuilder();
    }

    /** Hand-rolled builder so each test can override a single field without repeating the rest. */
    private static final class ConfigBuilder {
        private List<String> serverUris = List.of("ldap://directory.example.com:389");
        private String bindDn = "cn=kroxylicious,dc=example,dc=com";
        private String bindPassword = "secret";
        private String searchBase = "ou=people,dc=example,dc=com";
        private String searchFilterTemplate = "(uid={0})";
        private String memberOfAttribute = "memberOf";
        private String roleNameExtractionPattern = "cn=([^,]+),.*";
        private OnLookupFailure onLookupFailure = OnLookupFailure.FAIL;
        private Duration lookupTimeout = Duration.ofSeconds(5);
        private int executorPoolSize = 4;

        ConfigBuilder serverUris(List<String> serverUris) {
            this.serverUris = serverUris;
            return this;
        }

        ConfigBuilder bindDn(String bindDn) {
            this.bindDn = bindDn;
            return this;
        }

        ConfigBuilder searchBase(String searchBase) {
            this.searchBase = searchBase;
            return this;
        }

        ConfigBuilder searchFilterTemplate(String searchFilterTemplate) {
            this.searchFilterTemplate = searchFilterTemplate;
            return this;
        }

        ConfigBuilder memberOfAttribute(String memberOfAttribute) {
            this.memberOfAttribute = memberOfAttribute;
            return this;
        }

        ConfigBuilder roleNameExtractionPattern(String roleNameExtractionPattern) {
            this.roleNameExtractionPattern = roleNameExtractionPattern;
            return this;
        }

        ConfigBuilder onLookupFailure(OnLookupFailure onLookupFailure) {
            this.onLookupFailure = onLookupFailure;
            return this;
        }

        ConfigBuilder lookupTimeout(Duration lookupTimeout) {
            this.lookupTimeout = lookupTimeout;
            return this;
        }

        ConfigBuilder executorPoolSize(int executorPoolSize) {
            this.executorPoolSize = executorPoolSize;
            return this;
        }

        LdapRoleLookupConfig build() {
            return new LdapRoleLookupConfig(
                    serverUris, bindDn, bindPassword, searchBase, searchFilterTemplate, memberOfAttribute, roleNameExtractionPattern,
                    onLookupFailure, lookupTimeout, executorPoolSize);
        }
    }
}
