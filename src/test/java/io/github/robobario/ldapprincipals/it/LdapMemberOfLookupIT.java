package io.github.robobario.ldapprincipals.it;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SaslConfigs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;

import io.github.robobario.ldapprincipals.LdapSaslSubjectBuilderService;
import io.kroxylicious.filter.sasl.inspection.SaslInspection;
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
        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "alice", "alice-secret");

        assertThat(encodedSubject.split("\\|"))
                .containsExactlyInAnyOrder("User[name=alice]", "Role[name=" + KAFKA_ADMINS_GROUP_DN + "]");
    }

    @Test
    void producesAUserOnlySubjectWhenNoRolesFound(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "bob", password = "bob-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, "bob", "bob-secret");

        assertThat(encodedSubject).isEqualTo("User[name=bob]");
    }

    private String produceAndCaptureEncodedSubject(KafkaCluster cluster, Topic topic, String username, String password) throws Exception {
        var subjectBuilderConfig = new LdapSaslSubjectBuilderService.Config(
                List.of("ldap://localhost:" + directoryServer.getListenPort()),
                ADMIN_DN,
                ADMIN_PASSWORD,
                PEOPLE_DN,
                "(uid={0})",
                "memberOf",
                Duration.ofSeconds(5),
                2);

        var saslInspection = new NamedFilterDefinitionBuilder(SaslInspection.class.getName(), SaslInspection.class.getName())
                .withConfig(Map.of(
                        "enabledMechanisms", List.of("PLAIN"),
                        "subjectBuilder", LdapSaslSubjectBuilderService.class.getName(),
                        "subjectBuilderConfig", subjectBuilderConfig))
                .build();
        var subjectCapture = new NamedFilterDefinitionBuilder(
                SubjectCapturingFilterFactory.class.getName(), SubjectCapturingFilterFactory.class.getName()).build();

        var configBuilder = KroxyliciousConfigUtils.proxy(cluster)
                .addToFilterDefinitions(saslInspection, subjectCapture)
                .addToDefaultFilters(saslInspection.name(), subjectCapture.name());

        String jaasConfig = """
                org.apache.kafka.common.security.plain.PlainLoginModule required
                    username="%s"
                    password="%s";
                """.formatted(username, password);

        Map<String, Object> clientConfig = Map.of(
                CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT",
                SaslConfigs.SASL_MECHANISM, "PLAIN",
                SaslConfigs.SASL_JAAS_CONFIG, jaasConfig);

        try (var tester = kroxyliciousTester(configBuilder);
                var producer = tester.producer(clientConfig)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "my-key", "my-value")))
                    .succeedsWithin(Duration.ofSeconds(5));

            return SubjectCapturingFilter.CAPTURED_SUBJECTS.poll(10, TimeUnit.SECONDS);
        }
    }
}
