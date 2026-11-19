package io.github.robobario.ldapprincipals;

import java.util.concurrent.CompletionStage;

import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.Subject;

final class LdapSaslSubjectBuilder implements SaslSubjectBuilder {

    private final LdapRoleEnrichment enrichment;

    LdapSaslSubjectBuilder(LdapRoleEnrichment enrichment) {
        this.enrichment = enrichment;
    }

    @Override
    public CompletionStage<Subject> buildSaslSubject(Context context) {
        return enrichment.buildSubject(context.clientSaslContext().authorizationId());
    }
}
