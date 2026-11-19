package io.github.robobario.ldapprincipals;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import io.kroxylicious.proxy.authentication.SaslSubjectBuilder;
import io.kroxylicious.proxy.authentication.SaslSubjectBuilderService;
import io.kroxylicious.proxy.plugin.Plugin;

/**
 * Builds {@link SaslSubjectBuilder}s that enrich the SASL-authenticated identity with roles
 * read from an LDAP {@code memberOf} attribute. Plaintext LDAP only; TLS is not yet supported.
 */
@Plugin(configType = LdapSaslSubjectBuilderService.Config.class)
public class LdapSaslSubjectBuilderService implements SaslSubjectBuilderService<LdapSaslSubjectBuilderService.Config> {

    private RoleLookup roleLookup;
    private ExecutorService executor;
    private Duration lookupTimeout;

    @Override
    public void initialize(Config config) {
        this.roleLookup = new LdapRoleLookup(config);
        this.executor = Executors.newFixedThreadPool(config.executorPoolSize(), namedThreadFactory());
        this.lookupTimeout = config.lookupTimeout();
    }

    private static ThreadFactory namedThreadFactory() {
        var counter = new AtomicInteger();
        return runnable -> {
            var thread = new Thread(runnable, "ldap-role-lookup-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    @Override
    public SaslSubjectBuilder build() {
        return new LdapSaslSubjectBuilder(roleLookup, executor, lookupTimeout);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    /**
     * @param serverUris LDAP server URIs ({@code ldap://host:port}), tried in order until one succeeds.
     * @param bindDn DN of the service account used to query LDAP.
     * @param bindPassword password of the service account. Supplied inline; file-based secret sources are not yet supported.
     * @param searchBase base DN under which the identity's entry is searched for.
     * @param searchFilterTemplate search filter containing a {@code {0}} placeholder for the identity,
     *        e.g. {@code (uid={0})}. The identity is escaped before substitution.
     * @param memberOfAttribute name of the multi-valued attribute holding group membership. Defaults to {@code memberOf}.
     * @param lookupTimeout maximum time to wait for a lookup to complete.
     * @param executorPoolSize size of the dedicated executor LDAP operations run on.
     */
    public record Config(
            List<String> serverUris,
            String bindDn,
            String bindPassword,
            String searchBase,
            String searchFilterTemplate,
            String memberOfAttribute,
            Duration lookupTimeout,
            int executorPoolSize) {

        static final String IDENTITY_PLACEHOLDER = "{0}";
        private static final String DEFAULT_MEMBER_OF_ATTRIBUTE = "memberOf";

        public Config {
            if (serverUris == null || serverUris.isEmpty()) {
                throw new IllegalArgumentException("serverUris must not be empty");
            }
            serverUris = List.copyOf(serverUris);
            serverUris.forEach(Config::validateServerUri);
            requireNonBlank(bindDn, "bindDn");
            Objects.requireNonNull(bindPassword, "bindPassword must not be null");
            requireNonBlank(searchBase, "searchBase");
            requireNonBlank(searchFilterTemplate, "searchFilterTemplate");
            if (!searchFilterTemplate.contains(IDENTITY_PLACEHOLDER)) {
                throw new IllegalArgumentException(
                        "searchFilterTemplate must contain the '" + IDENTITY_PLACEHOLDER + "' placeholder");
            }
            memberOfAttribute = memberOfAttribute == null || memberOfAttribute.isBlank() ? DEFAULT_MEMBER_OF_ATTRIBUTE : memberOfAttribute;
            Objects.requireNonNull(lookupTimeout, "lookupTimeout must not be null");
            if (!lookupTimeout.isPositive()) {
                throw new IllegalArgumentException("lookupTimeout must be positive");
            }
            if (executorPoolSize < 1) {
                throw new IllegalArgumentException("executorPoolSize must be at least 1");
            }
        }

        private static void validateServerUri(String serverUri) {
            URI uri;
            try {
                uri = URI.create(serverUri);
            }
            catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid LDAP server URI '" + serverUri + "'", e);
            }
            if (!"ldap".equals(uri.getScheme())) {
                throw new IllegalArgumentException(
                        "Unsupported scheme in server URI '" + serverUri + "': only 'ldap://' is supported until TLS support is added");
            }
            if (uri.getHost() == null) {
                throw new IllegalArgumentException("Server URI '" + serverUri + "' is missing a host");
            }
        }

        private static void requireNonBlank(String value, String fieldName) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(fieldName + " must not be blank");
            }
        }

        @Override
        public String toString() {
            return "Config[serverUris=" + serverUris + ", bindDn=" + bindDn + ", bindPassword=***, searchBase=" + searchBase
                    + ", searchFilterTemplate=" + searchFilterTemplate + ", memberOfAttribute=" + memberOfAttribute
                    + ", lookupTimeout=" + lookupTimeout + ", executorPoolSize=" + executorPoolSize + "]";
        }
    }
}
