package io.github.robobario.ldapprincipals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Objects;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Truststore used to validate the LDAP server's certificate for LDAPS/StartTLS connections, e.g. a
 * private CA not present in the JVM's default truststore.
 *
 * @param path path to the truststore file.
 * @param password truststore password.
 * @param type truststore type, e.g. {@code JKS} or {@code PKCS12}. Defaults to {@code PKCS12}.
 */
public record LdapTrustStoreConfig(String path, String password, String type) {

    private static final String DEFAULT_TYPE = "PKCS12";

    public LdapTrustStoreConfig {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("trustStore.path must not be blank");
        }
        Objects.requireNonNull(password, "trustStore.password must not be null");
        type = type == null || type.isBlank() ? DEFAULT_TYPE : type;
        loadTrustManagers(path, password, type);
    }

    TrustManager[] toTrustManagers() {
        return loadTrustManagers(path, password, type);
    }

    private static TrustManager[] loadTrustManagers(String path, String password, String type) {
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(in, password.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            return trustManagerFactory.getTrustManagers();
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("Unable to load trust store '" + path + "': " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return "LdapTrustStoreConfig[path=" + path + ", password=***, type=" + type + "]";
    }
}
