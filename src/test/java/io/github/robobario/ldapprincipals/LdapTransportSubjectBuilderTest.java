package io.github.robobario.ldapprincipals;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
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

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @AfterEach
    void shutdown() {
        executor.shutdownNow();
    }

    @Test
    void buildsSubjectFromClientCertificateSubjectWithRoles() {
        certificateSubject("CN=alice,OU=users,DC=example,DC=com");
        var builder = builder(identity -> List.of("cn=kafka-admins,ou=groups,dc=example,dc=com"));

        var subject = builder.buildTransportSubject(context(Optional.of(tlsContext))).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice"), new Role("kafka-admins")));
    }

    @Test
    void buildsSubjectWithNoRolesWhenNoneFound() {
        certificateSubject("CN=alice,OU=users,DC=example,DC=com");
        var builder = builder(identity -> List.of());

        var subject = builder.buildTransportSubject(context(Optional.of(tlsContext))).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void failsWhenNoClientCertificatePresented() {
        when(tlsContext.clientCertificate()).thenReturn(Optional.empty());
        var builder = builder(identity -> List.of());

        var result = builder.buildTransportSubject(context(Optional.of(tlsContext)));

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(SubjectBuildingException.class);
    }

    @Test
    void failsWhenNotATlsConnection() {
        var builder = builder(identity -> List.of());

        var result = builder.buildTransportSubject(context(Optional.empty()));

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(SubjectBuildingException.class);
    }

    @Test
    void failsWhenCertificateSubjectLacksIdentityRdn() {
        certificateSubject("OU=users,DC=example,DC=com");
        var builder = builder(identity -> List.of());

        var result = builder.buildTransportSubject(context(Optional.of(tlsContext)));

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(SubjectBuildingException.class);
    }

    @Test
    void extractsIdentityFromRdnWithEscapedComma() {
        certificateSubject("CN=Doe\\, Jane,OU=users,DC=example,DC=com");
        var builder = builder(identity -> identity.equals("Doe, Jane") ? List.of("cn=kafka-admins,ou=groups,dc=example,dc=com") : List.of());

        var subject = builder.buildTransportSubject(context(Optional.of(tlsContext))).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("Doe, Jane"), new Role("kafka-admins")));
    }

    @Test
    void extractsIdentityWhenRdnIsNotLeading() {
        certificateSubject("OU=users,CN=alice,DC=example,DC=com");
        var builder = builder(identity -> identity.equals("alice") ? List.of("cn=kafka-admins,ou=groups,dc=example,dc=com") : List.of());

        var subject = builder.buildTransportSubject(context(Optional.of(tlsContext))).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice"), new Role("kafka-admins")));
    }

    private void certificateSubject(String dn) {
        when(clientCertificate.getSubjectX500Principal()).thenReturn(new X500Principal(dn));
        when(tlsContext.clientCertificate()).thenReturn(Optional.of(clientCertificate));
    }

    private LdapTransportSubjectBuilder builder(RoleLookup roleLookup) {
        var identityExtractor = new CertificateIdentityExtractor("CN");
        var enrichment = new LdapRoleEnrichment(roleLookup, new RoleNameExtractor("cn=([^,]+),.*"), executor, Duration.ofSeconds(5), OnLookupFailure.FAIL);
        return new LdapTransportSubjectBuilder(identityExtractor, enrichment);
    }

    private static TransportSubjectBuilder.Context context(Optional<ClientTlsContext> tlsContext) {
        return () -> tlsContext;
    }
}
