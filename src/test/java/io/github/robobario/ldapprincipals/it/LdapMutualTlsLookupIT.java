package io.github.robobario.ldapprincipals.it;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;

import io.github.robobario.ldapprincipals.LdapRoleLookupConfig;
import io.github.robobario.ldapprincipals.LdapTransportSubjectBuilderService;
import io.github.robobario.ldapprincipals.OnLookupFailure;
import io.kroxylicious.proxy.config.tls.TlsClientAuth;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.config.TransportSubjectBuilderDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.KeytoolCertificateGenerator;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.DEFAULT_CLUSTER_DEF_NAME;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.DEFAULT_CLUSTER_TARGET;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.OS_ASSIGNED_BOOTSTRAP;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.clusterDefinition;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.defaultPortIdentifiesNodeGatewayBuilder;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves {@link LdapTransportSubjectBuilderService} end to end: an mTLS-authenticated client's
 * certificate subject is looked up against a real (in-memory) LDAP directory's {@code memberOf}
 * attribute, and the resulting roles are observable in the {@code Subject} built for the connection.
 */
@ExtendWith(KafkaClusterExtension.class)
class LdapMutualTlsLookupIT {

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String PEOPLE_DN = "ou=people," + BASE_DN;
    private static final String ADMIN_DN = "cn=admin," + BASE_DN;
    private static final String ADMIN_PASSWORD = "admin-secret";
    private static final String KAFKA_ADMINS_GROUP_DN = "cn=kafka-admins,ou=groups," + BASE_DN;

    private static InMemoryDirectoryServer directoryServer;

    @TempDir
    private Path certsDirectory;

    private KeytoolCertificateGenerator downstreamCertificateGenerator;
    private KeytoolCertificateGenerator clientCertGenerator;
    private Path clientTrustStore;
    private Path proxyTrustStore;

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
    }

    @AfterAll
    static void stopDirectoryServer() {
        if (directoryServer != null) {
            directoryServer.shutDown(true);
        }
    }

    @BeforeEach
    void setUpCertificatesAndClearCapturedSubjects() throws Exception {
        SubjectCapturingFilter.CAPTURED_SUBJECTS.clear();

        downstreamCertificateGenerator = new KeytoolCertificateGenerator();
        downstreamCertificateGenerator.generateSelfSignedCertificateEntry("test@kroxylicious.io", "localhost", "KI", "kroxylicious.io", null, null, "US");
        clientTrustStore = certsDirectory.resolve("kafka.truststore.jks");
        downstreamCertificateGenerator.generateTrustStore(downstreamCertificateGenerator.getCertFilePath(), "client",
                clientTrustStore.toAbsolutePath().toString());

        clientCertGenerator = new KeytoolCertificateGenerator();
        clientCertGenerator.generateSelfSignedCertificateEntry("alice@kroxylicious.io", "alice", "users", "example.com", null, null, "US");
        proxyTrustStore = certsDirectory.resolve("proxy.truststore.jks");
        clientCertGenerator.generateTrustStore(clientCertGenerator.getCertFilePath(), "proxy",
                proxyTrustStore.toAbsolutePath().toString());
    }

    @Test
    void enrichesSubjectWithRolesFromMemberOf(KafkaCluster cluster, Topic topic) throws Exception {
        var subjectBuilderConfig = new LdapTransportSubjectBuilderService.Config(
                "CN",
                new LdapRoleLookupConfig(
                        List.of("ldap://localhost:" + directoryServer.getListenPort()),
                        ADMIN_DN, ADMIN_PASSWORD, PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                        OnLookupFailure.FAIL, Duration.ofSeconds(5), 2));

        var transportSubjectBuilder = new TransportSubjectBuilderDefinitionBuilder(LdapTransportSubjectBuilderService.class.getSimpleName())
                .withConfig(Map.of(
                        "identityRdnType", subjectBuilderConfig.identityRdnType(),
                        "ldap", subjectBuilderConfig.ldap()))
                .build();

        var subjectCapture = new NamedFilterDefinitionBuilder(
                SubjectCapturingFilterFactory.class.getName(), SubjectCapturingFilterFactory.class.getName()).build();

        var clusterDef = clusterDefinition(DEFAULT_CLUSTER_DEF_NAME, cluster);
        var configBuilder = KroxyliciousConfigUtils.baseConfigurationBuilder()
                .addToFilterDefinitions(subjectCapture)
                .addToDefaultFilters(subjectCapture.name())
                .addToClusterDefinitions(clusterDef)
                .addNewVirtualCluster()
                .withTarget(DEFAULT_CLUSTER_TARGET)
                .withName("demo")
                .withSubjectBuilder(transportSubjectBuilder)
                .addToGateways(
                        defaultPortIdentifiesNodeGatewayBuilder(OS_ASSIGNED_BOOTSTRAP)
                                .withNewTls()
                                .withNewKeyStoreKey()
                                .withStoreFile(downstreamCertificateGenerator.getKeyStoreLocation())
                                .withNewInlinePasswordStoreProvider(downstreamCertificateGenerator.getPassword())
                                .endKeyStoreKey()
                                .withNewTrustStoreTrust()
                                .withNewServerOptionsTrust()
                                .withClientAuth(TlsClientAuth.REQUIRED)
                                .endServerOptionsTrust()
                                .withStoreFile(proxyTrustStore.toAbsolutePath().toString())
                                .withNewInlinePasswordStoreProvider(clientCertGenerator.getPassword())
                                .endTrustStoreTrust()
                                .endTls()
                                .build())
                .endVirtualCluster();

        Map<String, Object> clientConfig = new HashMap<>(Map.of(
                CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, SecurityProtocol.SSL.name,
                SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, clientCertGenerator.getKeyStoreLocation(),
                SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, clientCertGenerator.getPassword(),
                SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, clientTrustStore.toAbsolutePath().toString(),
                SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, downstreamCertificateGenerator.getPassword()));

        try (var tester = kroxyliciousTester(configBuilder);
                var producer = tester.producer(clientConfig)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "my-key", "my-value")))
                    .succeedsWithin(Duration.ofSeconds(5));

            String encodedSubject = SubjectCapturingFilter.CAPTURED_SUBJECTS.poll(10, TimeUnit.SECONDS);

            assertThat(encodedSubject.split("\\|"))
                    .containsExactlyInAnyOrder("User[name=alice]", "Role[name=kafka-admins]");
        }
    }
}
