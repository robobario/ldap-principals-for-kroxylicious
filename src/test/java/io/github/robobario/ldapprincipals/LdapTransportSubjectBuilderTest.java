package io.github.robobario.ldapprincipals;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.CompletionException;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.tls.ClientTlsContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LdapTransportSubjectBuilderTest {

    @Mock
    ClientTlsContext tlsContext;

    @Mock
    X509Certificate clientCertificate;

    @Test
    void buildsSubjectFromClientCertificateSubject() {
        var dn = new X500Principal("CN=alice,OU=users,DC=example,DC=com");
        when(clientCertificate.getSubjectX500Principal()).thenReturn(dn);
        when(tlsContext.clientCertificate()).thenReturn(Optional.of(clientCertificate));

        var builder = new LdapTransportSubjectBuilder();
        var subject = builder.buildTransportSubject(context(Optional.of(tlsContext))).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User(dn.getName())));
    }

    @Test
    void failsWhenNoClientCertificatePresented() {
        when(tlsContext.clientCertificate()).thenReturn(Optional.empty());

        var builder = new LdapTransportSubjectBuilder();
        var result = builder.buildTransportSubject(context(Optional.of(tlsContext)));

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(SubjectBuildingException.class);
    }

    @Test
    void failsWhenNotATlsConnection() {
        var builder = new LdapTransportSubjectBuilder();
        var result = builder.buildTransportSubject(context(Optional.empty()));

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(SubjectBuildingException.class);
    }

    private static TransportSubjectBuilder.Context context(Optional<ClientTlsContext> tlsContext) {
        return () -> tlsContext;
    }
}
