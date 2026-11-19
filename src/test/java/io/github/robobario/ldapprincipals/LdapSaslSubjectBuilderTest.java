package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import io.kroxylicious.proxy.authentication.ClientSaslContext;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.tls.ClientTlsContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LdapSaslSubjectBuilderTest {

    @Test
    void buildsSubjectWithNoRoles() {
        var builder = builder(identity -> List.of());

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void buildsSubjectWithRoles() {
        var builder = builder(identity -> List.of("cn=kafka-admins,ou=groups,dc=example,dc=com"));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(
                new User("alice"),
                new Role("kafka-admins")));
    }

    @Test
    void dropsRawRolesThatDoNotMatchTheExtractionPattern() {
        var builder = builder(identity -> List.of("ou=people,dc=example,dc=com"));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void passesTheAuthorizationIdToTheLookup() {
        var seenIdentity = new AtomicReference<String>();
        var builder = builder(identity -> {
            seenIdentity.set(identity);
            return List.of();
        });

        builder.buildSaslSubject(context("bob")).toCompletableFuture().join();

        assertThat(seenIdentity).hasValue("bob");
    }

    @Test
    void failsTheStageWithSubjectBuildingExceptionWhenLookupFails() {
        var lookupFailure = new RuntimeException("connection refused");
        var builder = builder(identity -> {
            throw lookupFailure;
        });

        assertThatThrownBy(() -> builder.buildSaslSubject(context("alice")).toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .cause()
                .isInstanceOf(SubjectBuildingException.class)
                .hasCause(lookupFailure);
    }

    @Test
    void buildsUserOnlySubjectWhenLookupFailsAndPolicyIsAnonymousRoles() {
        var builder = new LdapSaslSubjectBuilder(identity -> {
            throw new RuntimeException("connection refused");
        }, extractor(), directExecutor(), Duration.ofSeconds(5), OnLookupFailure.ANONYMOUS_ROLES);

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void buildsUserOnlySubjectWhenLookupTimesOutAndPolicyIsAnonymousRoles() {
        var executor = Executors.newSingleThreadExecutor();
        try {
            var builder = new LdapSaslSubjectBuilder(identity -> {
                try {
                    Thread.sleep(500);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return List.of();
            }, extractor(), executor, Duration.ofMillis(50), OnLookupFailure.ANONYMOUS_ROLES);

            var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

            assertThat(subject).isEqualTo(new Subject(new User("alice")));
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    void failsTheStageWhenLookupExceedsTheTimeout() {
        var executor = Executors.newSingleThreadExecutor();
        try {
            var builder = new LdapSaslSubjectBuilder(identity -> {
                try {
                    Thread.sleep(500);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return List.of();
            }, extractor(), executor, Duration.ofMillis(50), OnLookupFailure.FAIL);

            assertThatThrownBy(() -> builder.buildSaslSubject(context("alice")).toCompletableFuture().join())
                    .isInstanceOf(CompletionException.class)
                    .cause()
                    .isInstanceOf(SubjectBuildingException.class);
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    void lookupRunsOnTheProvidedExecutorNotTheCallingThread() {
        var callingThread = Thread.currentThread();
        var lookupThread = new AtomicReference<Thread>();
        var executor = Executors.newSingleThreadExecutor();
        try {
            var builder = new LdapSaslSubjectBuilder(identity -> {
                lookupThread.set(Thread.currentThread());
                return List.of();
            }, extractor(), executor, Duration.ofSeconds(5), OnLookupFailure.FAIL);

            builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

            assertThat(lookupThread).doesNotHaveValue(callingThread);
        }
        finally {
            executor.shutdownNow();
        }
    }

    private static LdapSaslSubjectBuilder builder(RoleLookup roleLookup) {
        return new LdapSaslSubjectBuilder(roleLookup, extractor(), directExecutor(), Duration.ofSeconds(5), OnLookupFailure.FAIL);
    }

    private static RoleNameExtractor extractor() {
        return new RoleNameExtractor("cn=([^,]+),.*");
    }

    private static Executor directExecutor() {
        return Runnable::run;
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
