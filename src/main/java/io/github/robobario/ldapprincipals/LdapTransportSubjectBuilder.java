package io.github.robobario.ldapprincipals;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.authentication.User;

public class LdapTransportSubjectBuilder implements TransportSubjectBuilder {

    @Override
    public CompletionStage<Subject> buildTransportSubject(Context context) {
        return context.clientTlsContext()
                .flatMap(tls -> tls.clientCertificate())
                .map(cert -> cert.getSubjectX500Principal().getName())
                .map(name -> CompletableFuture.completedFuture(new Subject(new User(name))))
                .orElseGet(() -> CompletableFuture.failedFuture(
                        new SubjectBuildingException("No client certificate presented, cannot establish identity")));
    }
}
