package io.github.robobario.ldapprincipals;

import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilderService;
import io.kroxylicious.proxy.plugin.Plugin;

@Plugin(configType = Void.class)
public class LdapSaslSubjectBuilderService implements SaslSubjectBuilderService<Void> {

    @Override
    public void initialize(Void config) {
    }

    @Override
    public SaslSubjectBuilder build() {
        return new LdapSaslSubjectBuilder();
    }
}
