package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LdapRoleLookupTest {

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String PEOPLE_DN = "ou=people," + BASE_DN;
    private static final String ADMIN_DN = "cn=admin," + BASE_DN;
    private static final String ADMIN_PASSWORD = "admin-secret";
    private static final String GROUP_DN = "cn=kafka-admins,ou=groups," + BASE_DN;

    private static InMemoryDirectoryServer directoryServer;

    @BeforeAll
    static void startDirectoryServer() throws Exception {
        var config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.addAdditionalBindCredentials(ADMIN_DN, ADMIN_PASSWORD);
        config.setSchema(null);
        directoryServer = new InMemoryDirectoryServer(config);
        directoryServer.startListening();

        directoryServer.add(BASE_DN, new Attribute("objectClass", "top", "domain"), new Attribute("dc", "example"));
        directoryServer.add(PEOPLE_DN, new Attribute("objectClass", "top", "organizationalUnit"), new Attribute("ou", "people"));
        directoryServer.add("uid=alice," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "alice"),
                new Attribute("cn", "alice"),
                new Attribute("sn", "alice"),
                new Attribute("memberOf", GROUP_DN));
        directoryServer.add("uid=noroles," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "noroles"),
                new Attribute("cn", "noroles"),
                new Attribute("sn", "noroles"));
        directoryServer.add("cn=dupe-one," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "dupe"),
                new Attribute("cn", "dupe-one"),
                new Attribute("sn", "dupe-one"));
        directoryServer.add("cn=dupe-two," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "dupe"),
                new Attribute("cn", "dupe-two"),
                new Attribute("sn", "dupe-two"));
    }

    @AfterAll
    static void stopDirectoryServer() {
        if (directoryServer != null) {
            directoryServer.shutDown(true);
        }
    }

    @Test
    void returnsMemberOfValues() {
        assertThat(lookup().lookupRoles("alice")).containsExactly(GROUP_DN);
    }

    @Test
    void returnsEmptyWhenIdentityHasNoRoles() {
        assertThat(lookup().lookupRoles("noroles")).isEmpty();
    }

    @Test
    void returnsEmptyWhenIdentityNotFound() {
        assertThat(lookup().lookupRoles("ghost")).isEmpty();
    }

    @Test
    void failsWhenFilterMatchesMoreThanOneEntry() {
        assertThatThrownBy(() -> lookup().lookupRoles("dupe"))
                .isInstanceOf(LdapRoleLookupException.class)
                .hasMessageContaining("more than one entry");
    }

    private static LdapRoleLookup lookup() {
        return new LdapRoleLookup(new LdapSaslSubjectBuilderService.Config(
                List.of("ldap://localhost:" + directoryServer.getListenPort()),
                ADMIN_DN,
                ADMIN_PASSWORD,
                PEOPLE_DN,
                "(uid={0})",
                "memberOf",
                Duration.ofSeconds(5),
                2));
    }
}
