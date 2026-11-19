package io.github.robobario.ldapprincipals;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import io.kroxylicious.proxy.authentication.Principal;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.User;

final class LdapSaslSubjectBuilder implements SaslSubjectBuilder {

    private final RoleLookup roleLookup;
    private final Executor executor;
    private final Duration lookupTimeout;

    LdapSaslSubjectBuilder(RoleLookup roleLookup, Executor executor, Duration lookupTimeout) {
        this.roleLookup = roleLookup;
        this.executor = executor;
        this.lookupTimeout = lookupTimeout;
    }

    @Override
    public CompletionStage<Subject> buildSaslSubject(Context context) {
        String authorizationId = context.clientSaslContext().authorizationId();
        return CompletableFuture
                .supplyAsync(() -> roleLookup.lookupRoles(authorizationId), executor)
                .orTimeout(lookupTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .handle((rawRoles, failure) -> {
                    if (failure != null) {
                        throw new SubjectBuildingException(
                                "LDAP role lookup failed for identity '" + authorizationId + "'", unwrap(failure));
                    }
                    return toSubject(authorizationId, rawRoles);
                });
    }

    private static Subject toSubject(String authorizationId, List<String> rawRoles) {
        Set<Principal> principals = new HashSet<>();
        principals.add(new User(authorizationId));
        rawRoles.forEach(rawRole -> principals.add(new Role(rawRole)));
        return new Subject(principals);
    }

    private static Throwable unwrap(Throwable failure) {
        return failure instanceof CompletionException && failure.getCause() != null ? failure.getCause() : failure;
    }
}
