package io.github.robobario.ldapprincipals.it;

import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.Plugin;

@Plugin(configType = Void.class)
public class SubjectCapturingFilterFactory implements FilterFactory<Void, Void> {

    @Override
    public Void initialize(FilterFactoryContext context, Void config) {
        return null;
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Void config) {
        return new SubjectCapturingFilter();
    }
}
