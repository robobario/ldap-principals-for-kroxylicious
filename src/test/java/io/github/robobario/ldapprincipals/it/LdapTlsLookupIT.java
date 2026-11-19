package io.github.robobario.ldapprincipals.it;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SaslConfigs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Attribute;

import io.github.robobario.ldapprincipals.LdapRoleLookupConfig;
import io.github.robobario.ldapprincipals.LdapServerConfig;
import io.github.robobario.ldapprincipals.LdapSaslSubjectBuilderService;
import io.github.robobario.ldapprincipals.LdapTrustStoreConfig;
import io.github.robobario.ldapprincipals.OnLookupFailure;
import io.kroxylicious.filter.sasl.inspection.SaslInspection;
import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.KeytoolCertificateGenerator;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves TLS connectivity to the LDAP server: both LDAPS (implicit TLS) and StartTLS (upgraded
 * {@code ldap://}) handshakes succeed against a private-CA certificate trusted via a configured
 * {@link LdapTrustStoreConfig}, with {@code memberOf} roles observable end to end.
 */
@ExtendWith(KafkaClusterExtension.class)
class LdapTlsLookupIT {

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String PEOPLE_DN = "ou=people," + BASE_DN;
    private static final String ADMIN_DN = "cn=admin," + BASE_DN;
    private static final String ADMIN_PASSWORD = "admin-secret";
    private static final String KAFKA_ADMINS_GROUP_DN = "cn=kafka-admins,ou=groups," + BASE_DN;
    private static final String LDAPS_LISTENER = "ldaps";
    private static final String STARTTLS_LISTENER = "starttls";

    private static InMemoryDirectoryServer directoryServer;
    private static KeytoolCertificateGenerator serverCertGenerator;
    private static Path trustStorePath;

    @BeforeAll
    static void startDirectoryServer(@TempDir Path certsDirectory) throws Exception {
        serverCertGenerator = new KeytoolCertificateGenerator();
        serverCertGenerator.generateSelfSignedCertificateEntry("test@kroxylicious.io", "localhost", "KI", "kroxylicious.io", null, null, "US");
        trustStorePath = certsDirectory.resolve("ldap.truststore.p12");
        serverCertGenerator.generateTrustStore(serverCertGenerator.getCertFilePath(), "ldap-server", trustStorePath.toAbsolutePath().toString());

        SSLContext serverSslContext = buildServerSslContext();
        SSLServerSocketFactory ldapsSocketFactory = serverSslContext.getServerSocketFactory();
        SSLSocketFactory startTlsSocketFactory = serverSslContext.getSocketFactory();

        var config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.addAdditionalBindCredentials(ADMIN_DN, ADMIN_PASSWORD);
        config.setSchema(null);
        config.setListenerConfigs(List.of(
                InMemoryListenerConfig.createLDAPSConfig(LDAPS_LISTENER, InetAddress.getLoopbackAddress(), 0, ldapsSocketFactory, null),
                InMemoryListenerConfig.createLDAPConfig(STARTTLS_LISTENER, InetAddress.getLoopbackAddress(), 0, startTlsSocketFactory)));
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

    private static SSLContext buildServerSslContext() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(serverCertGenerator.getKeyStoreType());
        try (var in = new FileInputStream(serverCertGenerator.getKeyStoreLocation())) {
            keyStore.load(in, serverCertGenerator.getPassword().toCharArray());
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, serverCertGenerator.getPassword().toCharArray());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
        return sslContext;
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
    void enrichesSubjectWithRolesFromMemberOfOverLdaps(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        var subjectBuilderConfig = new LdapRoleLookupConfig(
                List.of(new LdapServerConfig("ldaps://localhost:" + directoryServer.getListenPort(LDAPS_LISTENER), false, trustStoreConfig())),
                ADMIN_DN, ADMIN_PASSWORD, PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                OnLookupFailure.FAIL, Duration.ofSeconds(5), 2, false);

        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, subjectBuilderConfig);

        assertThat(encodedSubject.split("\\|"))
                .containsExactlyInAnyOrder("User[name=alice]", "Role[name=kafka-admins]");
    }

    @Test
    void enrichesSubjectWithRolesFromMemberOfOverStartTls(@SaslMechanism(value = "PLAIN", principals = {
            @SaslMechanism.Principal(user = "alice", password = "alice-secret") }) KafkaCluster cluster, Topic topic) throws Exception {
        var subjectBuilderConfig = new LdapRoleLookupConfig(
                List.of(new LdapServerConfig("ldap://localhost:" + directoryServer.getListenPort(STARTTLS_LISTENER), true, trustStoreConfig())),
                ADMIN_DN, ADMIN_PASSWORD, PEOPLE_DN, "(uid={0})", "memberOf", "cn=([^,]+),.*",
                OnLookupFailure.FAIL, Duration.ofSeconds(5), 2, false);

        String encodedSubject = produceAndCaptureEncodedSubject(cluster, topic, subjectBuilderConfig);

        assertThat(encodedSubject.split("\\|"))
                .containsExactlyInAnyOrder("User[name=alice]", "Role[name=kafka-admins]");
    }

    private static LdapTrustStoreConfig trustStoreConfig() {
        return new LdapTrustStoreConfig(trustStorePath.toAbsolutePath().toString(), serverCertGenerator.getPassword(),
                serverCertGenerator.getTrustStoreType());
    }

    private String produceAndCaptureEncodedSubject(KafkaCluster cluster, Topic topic, LdapRoleLookupConfig subjectBuilderConfig) throws Exception {
        try (var tester = kroxyliciousTester(proxyConfig(cluster, subjectBuilderConfig));
                var producer = tester.producer(clientConfig("alice", "alice-secret"))) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "my-key", "my-value")))
                    .succeedsWithin(Duration.ofSeconds(5));

            return SubjectCapturingFilter.CAPTURED_SUBJECTS.poll(10, TimeUnit.SECONDS);
        }
    }

    private static ConfigurationBuilder proxyConfig(KafkaCluster cluster, LdapRoleLookupConfig subjectBuilderConfig) {
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
