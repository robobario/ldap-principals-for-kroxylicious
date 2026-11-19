package io.github.robobario.ldapprincipals;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.SubjectBuildingException;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.tls.ClientTlsContext;

final class LdapTransportSubjectBuilder implements TransportSubjectBuilder {

    private final CertificateIdentityExtractor identityExtractor;
    private final LdapRoleEnrichment enrichment;

    LdapTransportSubjectBuilder(CertificateIdentityExtractor identityExtractor, LdapRoleEnrichment enrichment) {
        this.identityExtractor = identityExtractor;
        this.enrichment = enrichment;
    }

    @Override
    public CompletionStage<Subject> buildTransportSubject(Context context) {
        Optional<ClientTlsContext> tlsContext = context.clientTlsContext();
        if (tlsContext.isEmpty()) {
            return failed("Connection is not TLS; the mTLS subject builder requires TLS with client authentication");
        }
        Optional<X509Certificate> certificate = tlsContext.get().clientCertificate();
        if (certificate.isEmpty()) {
            return failed("No client certificate presented on the TLS connection");
        }
        String subjectDn = certificate.get().getSubjectX500Principal().getName();
        return identityExtractor.extract(subjectDn)
                .<CompletionStage<Subject>> map(enrichment::buildSubject)
                .orElseGet(() -> failed("Client certificate subject '" + subjectDn + "' has no '"
                        + identityExtractor.rdnType() + "' RDN to use as the identity"));
    }

    private static CompletionStage<Subject> failed(String message) {
        return CompletableFuture.failedFuture(new SubjectBuildingException(message));
    }
}
