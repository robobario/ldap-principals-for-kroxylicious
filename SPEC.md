# kroxylicious-ldap-roles

## Purpose

Kroxylicious establishes a client's identity via SASL interception, SASL termination, or mTLS, and represents it as a `Subject` containing a `User` principal. This project adds LDAP-backed role enrichment: after identity is established, look up the user's group/role membership in LDAP and add `Role` principals to the `Subject`, so downstream `Authorizer` implementations can make role-based decisions.

Out of scope: authentication itself. This project only enriches an already-authenticated identity. It does not validate credentials and does not implement an `Authorizer`.

## Integration surface

Targets the kroxylicious-api `io.kroxylicious.proxy.authentication` package (the pre-1.0 API; the project will track the identity-api migration separately, see "Future migration" below).

Implement both of the following, since role lookup must work whether identity came from the transport layer (mTLS) or from SASL:

- `TransportSubjectBuilderService<C>` / `TransportSubjectBuilder` — mTLS case. Config'd on a virtual cluster. `buildTransportSubject(Context)` receives `Optional<ClientTlsContext>`.
- `SaslSubjectBuilderService<C>` / `SaslSubjectBuilder` — SASL case. Used by a SASL-terminating or SASL-inspecting filter. `buildSaslSubject(Context)` receives `ClientSaslContext` (authorization id) and optionally `ClientTlsContext`.

Both service interfaces are `AutoCloseable` with an `initialize(C config)` lifecycle method and a `build()` method returning the builder. Discovery is ServiceLoader-based (`META-INF/services`), standard for kroxylicious plugins — `@Plugin(configType = ...)` on the service class, config supplied as a record.

Both builder methods return `CompletionStage<Subject>`. On failure, fail the stage with `SubjectBuildingException` — do not throw synchronously, do not return a partially-built `Subject`.

`Subject` enforces at most one principal per singular type (`@Unique`/`SingularPrincipal`). `User` is singular. Define a `Role` principal type as non-singular, so a `Subject` can carry zero or more roles alongside the single `User`.

## Behavioral requirements

1. **Input**: extract the already-established identity name from the builder `Context` — SASL authorization id (`ClientSaslContext.authorizationId()`) or mTLS certificate subject/SAN (`ClientTlsContext`). Do not perform primary authentication; assume the name handed in is already trusted.

2. **Lookup**: query LDAP for the role/group membership of that identity. Support both common patterns:
   - `memberOf` attribute read directly off the user entry.
   - reverse group search (`(&(objectClass=groupOfNames)(member=<userDn>))`), for directories that don't maintain `memberOf`.

3. **Mapping**: map each LDAP result (typically a DN like `cn=kafka-admins,ou=groups,dc=example,dc=com`) to a role name. Support a configurable extraction rule (e.g. a regex against the DN, equivalent in spirit to the existing `sedLike` mapping rules used by kroxylicious's default principal adders), not a hardcoded `cn=` assumption.

4. **Output**: construct `new Subject(Set.of(userPrincipal, role1, role2, ...))`, preserving the `User` principal that was already implied by the authenticated identity. If LDAP returns no roles, that's a valid non-anonymous `Subject` carrying only the `User` principal.

5. **Non-blocking**: LDAP client libraries (JNDI `DirContext`, UnboundID, Apache LDAP API) are blocking. Never block a Netty event-loop thread. Run every LDAP operation on a dedicated, bounded executor owned by the service instance, and return the result via `CompletableFuture.supplyAsync(..., executor)`/`.thenApplyAsync(...)`. Size the executor and enforce a per-lookup timeout; a hung LDAP server must not exhaust the pool.

6. **Fail-safe default**: on LDAP error (connection failure, timeout, malformed response), the default behavior is to fail the stage with `SubjectBuildingException` rather than silently returning a `Subject` with no roles. Silently dropping roles is a privilege-escalation risk if a downstream default-allow authorizer treats "no roles claimed" as "no restriction" rather than "no grant" — don't assume the authorizer's semantics. Make this configurable (`onLookupFailure: fail | anonymous-roles`) but document the risk of the permissive option in the config javadoc, not just in this spec.

7. **Caching**: lookups happen once per connection (transport case) or once per SASL exchange (SASL case), not per request, so a TTL cache keyed by identity name is enough to absorb connection churn — this is a latency/availability optimization, not a correctness requirement. Bound cache size. Support negative caching (cache "no roles found" results too, with its own TTL) to avoid hammering LDAP for unknown users. Cache must be cleared/respect TTL independent of connection lifecycle — a role revoked in LDAP must eventually take effect without a kroxylicious restart.

## Configuration

Config record supplied via `initialize(C config)`. Required fields:

- LDAP server URI(s) — support a list for failover.
- Bind credentials for the service account used to query LDAP. Follow the password-provider pattern kroxylicious itself uses: support inline (dev only) and file-based (prod) secret sources, never a bare string-only option that encourages hardcoding.
- Connection security: LDAPS or StartTLS, plus trust store configuration for a private CA. Plain LDAP without TLS should require an explicit opt-in flag, not be the default.
- Search base DN and search filter template, parameterized by the extracted identity name.
- Role attribute name (default `memberOf`) and/or the group-search filter template, for directories without `memberOf`.
- Role name extraction rule (regex or equivalent) applied to each raw LDAP value.
- Lookup timeout and executor pool size.
- Cache TTL (positive and negative), max cache size.
- `onLookupFailure` policy (see above).

Validate all of this eagerly in the config record's compact constructor, matching the pattern kroxylicious's own `DefaultSaslSubjectBuilderService.Config`/`DefaultTransportSubjectBuilderService.Config` use — reject bad regex, bad filter templates, missing required fields at config-load time, not at first lookup.

## Packaging

Standard external kroxylicious plugin shape:

- Maven (or Gradle) module producing a jar with `kroxylicious-api` as a `provided`/compile-only dependency (don't shade it) and the LDAP client library as a regular dependency.
- `META-INF/services/io.kroxylicious.proxy.authentication.SaslSubjectBuilderService` and `.../TransportSubjectBuilderService` entries for ServiceLoader discovery.
- No dependency on `kroxylicious-runtime` internals — only `kroxylicious-api` public types.

## Testing

- Unit tests for the mapping/extraction logic without a real directory (pure function tests).
- Integration tests against a real or embedded LDAP server (e.g. UnboundID in-memory `InMemoryDirectoryServer`, or a Testcontainers OpenLDAP image) covering: `memberOf` path, reverse group-search path, no-roles-found, LDAP unreachable, timeout, TLS handshake.
- A test asserting the builder never blocks the calling thread for longer than a scheduling hop (i.e., the executor is actually used).
- Cache behavior: hit, miss, negative-cache hit, TTL expiry.

## Future migration

kroxylicious's own authentication API is mid-migration from `io.kroxylicious.proxy.authentication.Subject` to `io.kroxylicious.identity.Subject` (see kroxylicious design proposal 119). This project targets the old API now, by choice, to avoid needing a design proposal. When kroxylicious reaches the phase where `SaslSubjectBuilder`/`TransportSubjectBuilder` switch to `io.kroxylicious.identity.Subject`, expect a mechanical import-rename (an OpenRewrite recipe is planned upstream for exactly this). Keep the `Role` principal type and the LDAP lookup logic decoupled from the `Subject` type itself so that migration touches only the builder adapter layer, not the lookup/caching/mapping core.
