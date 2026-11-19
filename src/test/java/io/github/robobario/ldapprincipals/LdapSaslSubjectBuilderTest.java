package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
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

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @AfterEach
    void shutdown() {
        executor.shutdownNow();
    }

    @Test
    void buildsSubjectWithNoRoles() {
        var builder = builder(identity -> List.of(), OnLookupFailure.FAIL, Duration.ofSeconds(5));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void buildsSubjectWithRoles() {
        var builder = builder(identity -> List.of("cn=kafka-admins,ou=groups,dc=example,dc=com"), OnLookupFailure.FAIL, Duration.ofSeconds(5));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(
                new User("alice"),
                new Role("kafka-admins")));
    }

    @Test
    void dropsRawRolesThatDoNotMatchTheExtractionPattern() {
        var builder = builder(identity -> List.of("ou=people,dc=example,dc=com"), OnLookupFailure.FAIL, Duration.ofSeconds(5));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void passesTheAuthorizationIdToTheLookup() {
        var seenIdentity = new AtomicReference<String>();
        var builder = builder(identity -> {
            seenIdentity.set(identity);
            return List.of();
        }, OnLookupFailure.FAIL, Duration.ofSeconds(5));

        builder.buildSaslSubject(context("bob")).toCompletableFuture().join();

        assertThat(seenIdentity).hasValue("bob");
    }

    @Test
    void failsTheStageWithSubjectBuildingExceptionWhenLookupFails() {
        var lookupFailure = new RuntimeException("connection refused");
        var builder = builder(identity -> {
            throw lookupFailure;
        }, OnLookupFailure.FAIL, Duration.ofSeconds(5));

        assertThatThrownBy(() -> builder.buildSaslSubject(context("alice")).toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .cause()
                .isInstanceOf(SubjectBuildingException.class)
                .hasCause(lookupFailure);
    }

    @Test
    void buildsUserOnlySubjectWhenLookupFailsAndPolicyIsAnonymousRoles() {
        var builder = builder(identity -> {
            throw new RuntimeException("connection refused");
        }, OnLookupFailure.ANONYMOUS_ROLES, Duration.ofSeconds(5));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void failsTheStageWhenLookupExceedsTheTimeout() {
        var builder = builder(identity -> {
            try {
                Thread.sleep(500);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return List.of();
        }, OnLookupFailure.FAIL, Duration.ofMillis(50));

        assertThatThrownBy(() -> builder.buildSaslSubject(context("alice")).toCompletableFuture().join())
                .isInstanceOf(CompletionException.class)
                .cause()
                .isInstanceOf(SubjectBuildingException.class);
    }

    @Test
    void buildsUserOnlySubjectWhenLookupTimesOutAndPolicyIsAnonymousRoles() {
        var builder = builder(identity -> {
            try {
                Thread.sleep(500);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return List.of();
        }, OnLookupFailure.ANONYMOUS_ROLES, Duration.ofMillis(50));

        var subject = builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(subject).isEqualTo(new Subject(new User("alice")));
    }

    @Test
    void lookupRunsOnTheProvidedExecutorNotTheCallingThread() {
        var callingThread = Thread.currentThread();
        var lookupThread = new AtomicReference<Thread>();
        var builder = builder(identity -> {
            lookupThread.set(Thread.currentThread());
            return List.of();
        }, OnLookupFailure.FAIL, Duration.ofSeconds(5));

        builder.buildSaslSubject(context("alice")).toCompletableFuture().join();

        assertThat(lookupThread).doesNotHaveValue(callingThread);
    }

    private LdapSaslSubjectBuilder builder(RoleLookup roleLookup, OnLookupFailure onLookupFailure, Duration lookupTimeout) {
        var enrichment = new LdapRoleEnrichment(roleLookup, extractor(), executor, lookupTimeout, onLookupFailure);
        return new LdapSaslSubjectBuilder(enrichment);
    }

    private static RoleNameExtractor extractor() {
        return new RoleNameExtractor("cn=([^,]+),.*");
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
