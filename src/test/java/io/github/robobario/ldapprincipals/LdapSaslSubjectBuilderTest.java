package io.github.robobario.ldapprincipals;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.kroxylicious.proxy.authentication.ClientSaslContext;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.tls.ClientTlsContext;

import static org.assertj.core.api.Assertions.assertThat;

class LdapSaslSubjectBuilderTest {

    @Test
    void buildsSubjectFromAuthorizationId() {
        var builder = new LdapSaslSubjectBuilder();

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    private static SaslSubjectBuilder.Context context(String authorizationId) {
        return new SaslSubjectBuilder.Context() {
            @Override
            public Optional<ClientTlsContext> clientTlsContext() {
                return Optional.empty();
            }

            @Override
            public ClientSaslContext clientSaslContext() {
                return new ClientSaslContext() {
                    @Override
                    public String mechanismName() {
                        return "PLAIN";
                    }

                    @Override
                    public String authorizationId() {
                        return authorizationId;
                    }
                };
            }
        };
    }
}
