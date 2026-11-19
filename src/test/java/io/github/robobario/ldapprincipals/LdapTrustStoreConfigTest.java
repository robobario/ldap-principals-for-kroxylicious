package io.github.robobario.ldapprincipals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.kroxylicious.testing.kafka.common.KeytoolCertificateGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class LdapTrustStoreConfigTest {

    private static KeytoolCertificateGenerator certificateGenerator;

    @BeforeAll
    static void generateTrustStore() throws Exception {
        certificateGenerator = new KeytoolCertificateGenerator();
        certificateGenerator.generateSelfSignedCertificateEntry("test@kroxylicious.io", "localhost", "KI", "kroxylicious.io", null, null, "US");
        certificateGenerator.generateTrustStore(certificateGenerator.getCertFilePath(), "ldap-server");
    }

    @Test
    void acceptsAValidTrustStore() {
        assertThatNoException().isThrownBy(
                () -> new LdapTrustStoreConfig(certificateGenerator.getTrustStoreLocation(), certificateGenerator.getPassword(),
                        certificateGenerator.getTrustStoreType()));
    }

    @Test
    void defaultsBlankTypeToPkcs12() {
        var trustStore = new LdapTrustStoreConfig(certificateGenerator.getTrustStoreLocation(), certificateGenerator.getPassword(), " ");

        assertThat(trustStore.type()).isEqualTo("PKCS12");
    }

    @Test
    void rejectsBlankPath() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LdapTrustStoreConfig(" ", certificateGenerator.getPassword(), "PKCS12"));
    }

    @Test
    void rejectsMissingFile() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new LdapTrustStoreConfig("/no/such/truststore.p12", certificateGenerator.getPassword(), "PKCS12"));
    }

    @Test
    void rejectsWrongPassword() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new LdapTrustStoreConfig(certificateGenerator.getTrustStoreLocation(), "wrong-password", "PKCS12"));
    }

    @Test
    void rejectsUnknownType() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new LdapTrustStoreConfig(certificateGenerator.getTrustStoreLocation(), certificateGenerator.getPassword(), "NO-SUCH-TYPE"));
    }

    @Test
    void toStringDoesNotLeakPassword() {
        var trustStore = new LdapTrustStoreConfig(certificateGenerator.getTrustStoreLocation(), certificateGenerator.getPassword(), "PKCS12");

        assertThat(trustStore.toString()).doesNotContain(certificateGenerator.getPassword());
    }
}
