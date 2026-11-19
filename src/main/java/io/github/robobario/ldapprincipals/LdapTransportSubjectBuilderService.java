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

    private RoleNameExtractor identityExtractor;
    private LdapRoleEnrichment enrichment;

    @Override
    public void initialize(Config config) {
        this.identityExtractor = new RoleNameExtractor(config.identityExtractionPattern());
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
     * @param identityExtractionPattern regex matched against the client certificate's subject DN to derive the
     *        identity, e.g. {@code CN=([^,]+),.*}. Must contain at least one capturing group; a subject that
     *        doesn't match fails subject building.
     * @param ldap LDAP connectivity and role-lookup configuration, shared with {@link LdapSaslSubjectBuilderService}.
     */
    public record Config(String identityExtractionPattern, LdapRoleLookupConfig ldap) {
        public Config {
            RoleNameExtractor.validatePattern(identityExtractionPattern, "identityExtractionPattern");
            Objects.requireNonNull(ldap, "ldap must not be null");
        }
    }
}
