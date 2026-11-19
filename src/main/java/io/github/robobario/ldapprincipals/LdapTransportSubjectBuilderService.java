package io.github.robobario.ldapprincipals;

import io.kroxylicious.proxy.authentication.TransportSubjectBuilder;
import io.kroxylicious.proxy.authentication.TransportSubjectBuilderService;
import io.kroxylicious.proxy.plugin.Plugin;

@Plugin(configType = Void.class)
public class LdapTransportSubjectBuilderService implements TransportSubjectBuilderService<Void> {

    @Override
    public void initialize(Void config) {
    }

    @Override
    public TransportSubjectBuilder build() {
        return new LdapTransportSubjectBuilder();
    }
}
