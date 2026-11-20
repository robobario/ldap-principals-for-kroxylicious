# ldap-principals-for-kroxylicious

LDAP-backed role enrichment for kroxylicious. After a client authenticates, this
plugin looks up the identity's group membership in LDAP and adds `Role` principals
to the `Subject`, so a downstream `Authorizer` can make role-based decisions.

It plugs in through the `SaslSubjectBuilder` and `TransportSubjectBuilder`
extension points from kroxylicious-api. See [SPEC.md](SPEC.md) for the full design.

## What it does

- Takes the already-established identity (SASL authorization id, or an RDN of the
  mTLS client certificate's subject DN). It does not perform primary authentication.
- Binds to LDAP with a service account, searches for the identity's entry, and reads
  its `memberOf` values.
- Maps each raw value (typically a group DN) to a role name with a configurable regex.
- Builds a `Subject` carrying the original `User` plus a `Role` per mapped group.

## Demo

[demo/](demo/) is a runnable end-to-end example: Kafka, an LDAP directory with
two users in different groups, and kroxylicious with SASL termination, this
plugin, and an ACL authorizer. It shows one user's role granted access to a
topic while the other is denied. Run `./demo/up.sh && ./demo/test.sh`.

## Builders

- `LdapSaslSubjectBuilderService` — for SASL. Used by a SASL-terminating or
  SASL-inspecting filter. Config type is `LdapRoleLookupConfig` (below) directly.
- `LdapTransportSubjectBuilderService` — for mTLS. Configured on a virtual cluster.
  Config adds `identityRdnType` (the subject-DN RDN used as the identity, e.g. `CN`)
  around the shared `ldap` block.

## Configuration

`LdapRoleLookupConfig` (the SASL config, and the `ldap` block of the transport config):

| Field | Meaning |
|---|---|
| `servers` | LDAP servers tried in order. Each has `uri` (`ldap://` or `ldaps://`), optional `startTls`, optional `trustStore`. |
| `bindDn` | Service-account DN used to query LDAP. |
| `bindPassword` | Service-account secret as a kroxylicious password provider: `{password: ...}` (inline) or `{passwordFile: ...}` (file). |
| `searchBase` | Base DN the identity's entry is searched under. |
| `searchFilterTemplate` | Search filter with a `{0}` placeholder for the identity, e.g. `(uid={0})`. The identity is escaped before substitution. |
| `memberOfAttribute` | Group-membership attribute. Defaults to `memberOf`. |
| `roleNameExtractionPattern` | Regex matched against each raw value; capturing group 1 is the role name, e.g. `cn=([^,]+),.*`. Non-matching values contribute no role. |
| `onLookupFailure` | `fail` (default, deny the connection) or `anonymous-roles` (build a `User`-only `Subject`). |
| `lookupTimeout` | Max time per lookup, e.g. `5s`. |
| `executorPoolSize` | Size of the dedicated executor LDAP operations run on. |
| `allowPlaintextLdap` | Opt-in required to use a plaintext `ldap://` server without `startTls`. |

Each `servers[].trustStore` (optional, for a private CA on `ldaps://`/`startTls`) has
`path`, `password`, and `type` (defaults to `PKCS12`).

Every field is validated eagerly at config-load time, including truststore loading
and bind-password resolution, so a bad config fails on startup rather than first lookup.

### SASL example

```yaml
filters:
  - type: SaslInspection
    config:
      enabledMechanisms: [PLAIN]
      subjectBuilder: io.github.robobario.ldapprincipals.LdapSaslSubjectBuilderService
      subjectBuilderConfig:
        servers:
          - uri: ldaps://directory.example.com:636
        bindDn: cn=kroxylicious,dc=example,dc=com
        bindPassword:
          passwordFile: /etc/kroxylicious/ldap-bind.pw
        searchBase: ou=people,dc=example,dc=com
        searchFilterTemplate: (uid={0})
        roleNameExtractionPattern: cn=([^,]+),.*
        lookupTimeout: 5s
        executorPoolSize: 4
```

### mTLS example

```yaml
virtualClusters:
  - name: demo
    subjectBuilder:
      type: LdapTransportSubjectBuilderService
      config:
        identityRdnType: CN
        ldap:
          servers:
            - uri: ldaps://directory.example.com:636
          bindDn: cn=kroxylicious,dc=example,dc=com
          bindPassword:
            passwordFile: /etc/kroxylicious/ldap-bind.pw
          searchBase: ou=people,dc=example,dc=com
          searchFilterTemplate: (uid={0})
          roleNameExtractionPattern: cn=([^,]+),.*
          lookupTimeout: 5s
          executorPoolSize: 4
```

## Build

```
mvn clean verify
```

Unit tests run under surefire; integration tests (an embedded UnboundID directory and
an in-VM kroxylicious proxy) run under failsafe during `verify`.

## Publishing

Maven Central via the Sonatype Central Portal, built with GitHub Actions
(ci / publish-snapshot / release workflows, dependabot). Setup steps:
[.github/AUTOMATION.md](.github/AUTOMATION.md).
