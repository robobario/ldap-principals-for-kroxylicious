package io.github.robobario.ldapprincipals;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;

public class LdapSaslSubjectBuilder implements SaslSubjectBuilder {

    @Override
    public CompletionStage<Subject> buildSaslSubject(Context context) {
        String authorizationId = context.clientSaslContext().authorizationId();
        return CompletableFuture.completedFuture(new Subject(new User(authorizationId)));
    }
}
