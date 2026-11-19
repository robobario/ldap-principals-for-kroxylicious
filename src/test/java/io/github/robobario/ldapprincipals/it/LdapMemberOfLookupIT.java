package io.github.robobario.ldapprincipals.it;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;

import io.github.robobario.ldapprincipals.LdapRoleLookupConfig;
import io.github.robobario.ldapprincipals.LdapServerConfig;
import io.github.robobario.ldapprincipals.LdapSaslSubjectBuilderService;
import io.github.robobario.ldapprincipals.OnLookupFailure;
import io.kroxylicious.filter.sasl.inspection.SaslInspection;
import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.proxy.config.secret.InlinePassword;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves {@link LdapSaslSubjectBuilderService} end to end: a SASL PLAIN authenticated client's
 * authorization id is looked up against a real (in-memory) LDAP directory's {@code memberOf}
 * attribute, and the resulting roles are observable in the {@code Subject} built for the connection.
 * Also covers the {@code onLookupFailure} policy against an unreachable directory and a hung one.
 */
@ExtendWith(KafkaClusterExtension.class)
class LdapMemberOfLookupIT {

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String PEOPLE_DN = "ou=people," + BASE_DN;
    private static final String ADMIN_DN = "cn=admin," + BASE_DN;
    private static final String ADMIN_PASSWORD = "admin-secret";
    private static final String KAFKA_ADMINS_GROUP_DN = "cn=kafka-admins,ou=groups," + BASE_DN;

    private static InMemoryDirectoryServer directoryServer;

    @BeforeAll
    static void startDirectoryServer() throws Exception {
        var config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.addAdditionalBindCredentials(ADMIN_DN, ADMIN_PASSWORD);
        config.setSchema(null);
        directoryServer = new InMemoryDirectoryServer(config);
        directoryServer.startListening();

        directoryServer.add(BASE_DN,
                new Attribute("objectClass", "top", "domain"),
                new Attribute("dc", "example"));
        directoryServer.add(PEOPLE_DN,
                new Attribute("objectClass", "top", "organizationalUnit"),
                new Attribute("ou", "people"));
        directoryServer.add("ou=groups," + BASE_DN,
                new Attribute("objectClass", "top", "organizationalUnit"),
                new Attribute("ou", "groups"));
        directoryServer.add("uid=alice," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "alice"),
                new Attribute("cn", "alice"),
                new Attribute("sn", "alice"),
                new Attribute("memberOf", KAFKA_ADMINS_GROUP_DN));
        directoryServer.add("uid=bob," + PEOPLE_DN,
                new Attribute("objectClass", "top", "person"),
                new Attribute("uid", "bob"),
                new Attribute("cn", "bob"),
                new Attribute("sn", "bob"));
    }

    @AfterAll
    static void stopDirectoryServer() {
        if (directoryServer != null) {
            directoryServer.shutDown(true);
        }
    }

    @BeforeEach
    void clearCapturedSubjects() {
        SubjectCapturingFilter.CAPTURED_SUBJECTS.clear();
    }

    @Test
    void enrichesSubjectWithRolesFromMemberOf(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "alice", "alice-secret", memberOfConfig(OnLookupFailure.FAIL));

        assertThat(encodedSubject.split("\\|"))
                .containsExactlyInAnyOrder("User[name=alice]", "Role[name=kafka-admins]");
    }

    @Test
    void producesAUserOnlySubjectWhenNoRolesFound(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "bob", password = "bob-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "bob", "bob-secret", memberOfConfig(OnLookupFailure.FAIL));

        assertThat(encodedSubject).isEqualTo("User[name=bob]");
    }

    @Test
    void failsAuthenticationWhenLdapIsUnreachable(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) {
        assertAuthenticationFails(cluster, topic, "alice", "alice-secret", unreachableConfig(OnLookupFailure.FAIL));
    }

    @Test
    void buildsUserOnlySubjectWhenLdapIsUnreachableAndPolicyIsAnonymousRoles(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "alice", "alice-secret",
                unreachableConfig(OnLookupFailure.ANONYMOUS_ROLES));

        assertThat(encodedSubject).isEqualTo("User[name=alice]");
    }

    @Test
    void failsAuthenticationWhenLookupTimesOut(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        try (var blackhole = startBlackhole()) {
            assertAuthenticationFails(cluster, topic, "alice", "alice-secret", hungConfig(blackhole, OnLookupFailure.FAIL));
        }
    }

    @Test
    void buildsUserOnlySubjectWhenLookupTimesOutAndPolicyIsAnonymousRoles(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        try (var blackhole = startBlackhole()) {
            String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "alice", "alice-secret",
                    hungConfig(blackhole, OnLookupFailure.ANONYMOUS_ROLES));

            assertThat(encodedSubject).isEqualTo("User[name=alice]");
        }
    }

    private static LdapRoleLookupConfig memberOfConfig(OnLookupFailure onLookupFailure) {
        return new LdapRoleLookupConfig(
                List.of(new LdapServerConfig("ldap://localhost:" + directoryServer.getListenPort(), false, null)),
                ADMIN_DN, new InlinePassword(ADMIN_PASSWORD), PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                onLookupFailure, Duration.ofSeconds(5), 2, true);
    }

    private static LdapRoleLookupConfig unreachableConfig(OnLookupFailure onLookupFailure) {
        return new LdapRoleLookupConfig(
                List.of(new LdapServerConfig("ldap://localhost:1", false, null)),
                ADMIN_DN, new InlinePassword(ADMIN_PASSWORD), PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                onLookupFailure, Duration.ofSeconds(2), 2, true);
    }

    private static LdapRoleLookupConfig hungConfig(ServerSocket blackhole, OnLookupFailure onLookupFailure) {
        return new LdapRoleLookupConfig(
                List.of(new LdapServerConfig("ldap://localhost:" + blackhole.getLocalPort(), false, null)),
                ADMIN_DN, new InlinePassword(ADMIN_PASSWORD), PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                onLookupFailure, Duration.ofMillis(300), 2, true);
    }

    /** Accepts connections but never replies, so a client hangs until its own lookup timeout fires. */
    private static ServerSocket startBlackhole() throws IOException {
        var serverSocket = new ServerSocket(0);
        var acceptThread = new Thread(() -> {
            while (!serverSocket.isClosed()) {
                try {
                    serverSocket.accept();
                }
                catch (IOException e) {
                    break;
                }
            }
        });
        acceptThread.setDaemon(true);
        acceptThread.start();
        return serverSocket;
    }

    private void assertAuthenticationFails(KafkaCluster cluster, Topic topic, String username, String password,
                                           LdapRoleLookupConfig subjectBuilderConfig) {
        try (var tester = kroxyliciousTester(proxyConfig(cluster, subjectBuilderConfig));
                var producer = tester.producer(clientConfig(username, password))) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "my-key", "my-value")))
                    .failsWithin(Duration.ofSeconds(5))
                    .withThrowableOfType(ExecutionException.class)
                    .withCauseExactlyInstanceOf(IllegalSaslStateException.class);
        }
    }

    private String produceAndCaptureEncodedSubject(KafkaCluster cluster, Topic topic, String username, String password,
                                                    LdapRoleLookupConfig subjectBuilderConfig) throws Exception {
        try (var tester = kroxyliciousTester(proxyConfig(cluster, subjectBuilderConfig));
                var producer = tester.producer(clientConfig(username, password))) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "my-key", "my-value")))
                    .succeedsWithin(Duration.ofSeconds(5));

            return SubjectCapturingFilter.CAPTURED_SUBJECTS.poll(10, TimeUnit.SECONDS);
        }
    }

    private static ConfigurationBuilder proxyConfig(KafkaCluster cluster,
                                                     LdapRoleLookupConfig subjectBuilderConfig) {
        var saslInspection = new NamedFilterDefinitionBuilder(SaslInspection.class.getName(), SaslInspection.class.getName())
                .withConfig(Map.of(
                        "enabledMechanisms", List.of("PLAIN"),
                        "subjectBuilder", LdapSaslSubjectBuilderService.class.getName(),
                        "subjectBuilderConfig", subjectBuilderConfig))
                .build();
        var subjectCapture = new NamedFilterDefinitionBuilder(
                SubjectCapturingFilterFactory.class.getName(), SubjectCapturingFilterFactory.class.getName()).build();

        return KroxyliciousConfigUtils.proxy(cluster)
                .addToFilterDefinitions(saslInspection, subjectCapture)
                .addToDefaultFilters(saslInspection.name(), subjectCapture.name());
    }

    private static Map<String, Object> clientConfig(String username, String password) {
        String jaasConfig = """
                org.apache.kafka.common.security.plain.PlainLoginModule required
                    username="%s"
                    password="%s";
                """.formatted(username, password);

        return Map.of(
                CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT",
                SaslConfigs.SASL_MECHANISM, "PLAIN",
                SaslConfigs.SASL_JAAS_CONFIG, jaasConfig);
    }
}
