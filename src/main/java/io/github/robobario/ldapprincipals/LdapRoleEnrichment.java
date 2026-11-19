package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import io.kroxylicious.proxy.authentication.Principal;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.User;

/**
 * Builds a {@link Subject} for an already-authenticated identity by looking up its roles in LDAP.
 * Shared by the SASL and transport builder adapters: they differ only in how they establish the
 * identity, not in how a {@code Subject} is built from one.
 */
final class LdapRoleEnrichment implements AutoCloseable {

    private final RoleLookup roleLookup;
    private final RoleNameExtractor roleNameExtractor;
    private final ExecutorService executor;
    private final Duration lookupTimeout;
    private final OnLookupFailure onLookupFailure;

    LdapRoleEnrichment(LdapRoleLookupConfig config) {
        this(new LdapRoleLookup(config), new RoleNameExtractor(config.roleNameExtractionPattern()),
                Executors.newFixedThreadPool(config.executorPoolSize(), namedThreadFactory()),
                config.lookupTimeout(), config.onLookupFailure());
    }

    LdapRoleEnrichment(RoleLookup roleLookup, RoleNameExtractor roleNameExtractor, ExecutorService executor,
                       Duration lookupTimeout, OnLookupFailure onLookupFailure) {
        this.roleLookup = roleLookup;
        this.roleNameExtractor = roleNameExtractor;
        this.executor = executor;
        this.lookupTimeout = lookupTimeout;
        this.onLookupFailure = onLookupFailure;
    }

    CompletionStage<Subject> buildSubject(String identity) {
        return CompletableFuture
                .supplyAsync(() -> roleLookup.lookupRoles(identity), executor)
                .orTimeout(lookupTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .handle((rawRoles, failure) -> {
                    if (failure != null) {
                        if (onLookupFailure == OnLookupFailure.ANONYMOUS_ROLES) {
                            return new Subject(new User(identity));
                        }
                        throw new SubjectBuildingException(
                                "LDAP role lookup failed for identity '" + identity + "'", unwrap(failure));
                    }
                    return toSubject(identity, rawRoles);
                });
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    private Subject toSubject(String identity, List<String> rawRoles) {
        Set<Principal> principals = new HashSet<>();
        principals.add(new User(identity));
        rawRoles.stream()
                .map(roleNameExtractor::extract)
                .flatMap(Optional::stream)
                .forEach(roleName -> principals.add(new Role(roleName)));
        return new Subject(principals);
    }

    private static Throwable unwrap(Throwable failure) {
        return failure instanceof CompletionException && failure.getCause() != null ? failure.getCause() : failure;
    }

    private static ThreadFactory namedThreadFactory() {
        var counter = new AtomicInteger();
        return runnable -> {
            var thread = new Thread(runnable, "ldap-role-lookup-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
