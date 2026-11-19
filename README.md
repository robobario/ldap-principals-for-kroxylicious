# ldap-principals-for-kroxylicious

LDAP role enrichment for kroxylicious. Adds `Role` principals to a `Subject`
after SASL/mTLS auth, via `SaslSubjectBuilder`/`TransportSubjectBuilder` from
kroxylicious-api. See [SPEC.md](SPEC.md) for full design.

## Status

Scaffold stage. Builders do identity passthrough only (SASL authz id / TLS
cert subject -> `User` principal). No LDAP lookup yet.

## Build

```
mvn clean verify
```

## Publishing

Maven Central via Sonatype Central Portal, built with GitHub Actions
(ci/publish-snapshot/release workflows, dependabot). Setup steps:
[.github/README.md](.github/README.md).
