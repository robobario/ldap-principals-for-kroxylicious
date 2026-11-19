package io.github.robobario.ldapprincipals;

import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilderService;
import io.kroxylicious.proxy.plugin.Plugin;

/**
 * Builds {@link SaslSubjectBuilder}s that enrich the SASL-authenticated identity with roles
 * read from an LDAP {@code memberOf} attribute.
 */
@Plugin(configType = LdapRoleLookupConfig.class)
public class LdapSaslSubjectBuilderService implements SaslSubjectBuilderService<LdapRoleLookupConfig> {

    private LdapRoleEnrichment enrichment;

    @Override
    public void initialize(LdapRoleLookupConfig config) {
        this.enrichment = new LdapRoleEnrichment(config);
    }

    @Override
    public SaslSubjectBuilder build() {
        return new LdapSaslSubjectBuilder(enrichment);
    }

    @Override
    public void close() {
        if (enrichment != null) {
            enrichment.close();
        }
    }
}
