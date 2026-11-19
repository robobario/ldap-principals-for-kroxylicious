package io.github.robobario.ldapprincipals;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.tls.ClientTlsContext;

final class LdapTransportSubjectBuilder implements TransportSubjectBuilder {

    private final RoleNameExtractor identityExtractor;
    private final LdapRoleEnrichment enrichment;

    LdapTransportSubjectBuilder(RoleNameExtractor identityExtractor, LdapRoleEnrichment enrichment) {
        this.identityExtractor = identityExtractor;
        this.enrichment = enrichment;
    }

    @Override
    public CompletionStage<Subject> buildTransportSubject(Context context) {
        return context.clientTlsContext()
                .flatMap(ClientTlsContext::clientCertificate)
                .map(cert -> cert.getSubjectX500Principal().getName())
                .flatMap(identityExtractor::extract)
                .<CompletionStage<Subject>> map(enrichment::buildSubject)
                .orElseGet(() -> CompletableFuture.failedFuture(new SubjectBuildingException(
                        "No client certificate presented, or its subject did not match the configured identityExtractionPattern")));
    }
}
