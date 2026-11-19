package io.github.robobario.ldapprincipals;

import java.util.Objects;

import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilderService;
import io.kroxylicious.proxy.plugin.Plugin;

/**
 * Builds {@link TransportSubjectBuilder}s that enrich an mTLS-authenticated identity with roles
 * read from an LDAP {@code memberOf} attribute.
 */
@Plugin(configType = LdapTransportSubjectBuilderService.Config.class)
public class LdapTransportSubjectBuilderService implements TransportSubjectBuilderService<LdapTransportSubjectBuilderService.Config> {

    private CertificateIdentityExtractor identityExtractor;
    private LdapRoleEnrichment enrichment;

    @Override
    public void initialize(Config config) {
        this.identityExtractor = new CertificateIdentityExtractor(config.identityRdnType());
        this.enrichment = new LdapRoleEnrichment(config.ldap());
    }

    @Override
    public TransportSubjectBuilder build() {
        return new LdapTransportSubjectBuilder(identityExtractor, enrichment);
    }

    @Override
    public void close() {
        if (enrichment != null) {
            enrichment.close();
        }
    }

    /**
     * @param identityRdnType RDN type selected from the client certificate's subject DN as the identity, e.g.
     *        {@code CN}. A subject lacking that RDN fails subject building.
     * @param ldap LDAP connectivity and role-lookup configuration, shared with {@link LdapSaslSubjectBuilderService}.
     */
    public record Config(String identityRdnType, LdapRoleLookupConfig ldap) {
        public Config {
            CertificateIdentityExtractor.validateRdnType(identityRdnType, "identityRdnType");
            Objects.requireNonNull(ldap, "ldap must not be null");
        }
    }
}
