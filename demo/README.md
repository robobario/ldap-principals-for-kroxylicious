# Demo: LDAP roles driving proxy-side authorization

This demo shows the plugin turning LDAP group membership into authorization
decisions at the proxy. Two users authenticate to kroxylicious with SCRAM.
The plugin looks each one up in LDAP and attaches a `Role` principal from their
group. An ACL then allows one role and denies the other, with the backing Kafka
broker never seeing a credential.

- `alice` is in LDAP group `role-a`, mapped to `Role[role-a]`.
- `bob` is in LDAP group `role-b`, mapped to `Role[role-b]`.
- The ACL allows `role-a` to read and write `demo-topic`; everything else is denied.

Result: alice produces and consumes; bob gets `TopicAuthorizationException`.

## Prerequisites

- `podman` (or Docker, via `CONTAINER_ENGINE=docker`)
- `gh` (GitHub CLI, authenticated) to download the release artifacts
- Java 17+ on the host (kroxylicious runs as a host process)
- Free host ports 9092 (Kafka), 9192 (proxy), 1389 (LDAP), 9190 (proxy management)

## Run

```bash
./demo/up.sh      # download, start Kafka + LDAP + proxy, load users/groups
./demo/test.sh    # prove alice is allowed and bob is denied
./demo/down.sh    # stop the proxy and remove the containers
```

`up.sh` is idempotent and prints the path of the rendered proxy config.
`down.sh --purge` also deletes `.work/` (downloads and generated secrets).

Set `CONTAINER_ENGINE=docker` to use Docker instead of the default podman:

```bash
CONTAINER_ENGINE=docker ./demo/up.sh
```

### Try it interactively

With the stack up, open a producer and a consumer as a given user and fire off
records by hand:

```bash
./demo/producer.sh alice   # type records, Enter to send, Ctrl-D to quit
./demo/consumer.sh alice   # follows the topic, Ctrl-C to quit
./demo/producer.sh bob     # same, but every send is denied
```

Both take a user name matching a file in `client/` (alice or bob).

## How it fits together

```
 client (SCRAM)                   kroxylicious                         Kafka
 alice / bob  ───────▶  SaslTermination ──▶ Authorization  ──────▶  apache/kafka
                        (SCRAM-SHA-256)      (ACL authorizer)        (PLAINTEXT,
                        + LDAP plugin                                 no auth)
                          subjectBuilder           │
                              │                     │
                              ▼                     ▼
                        LDAP memberOf          acl-rules.txt
                        -> Role principal      role-a allow / else deny
```

1. **SASL termination.** The `SaslTermination` filter authenticates the client
   with SCRAM-SHA-256 against a local credential file
   (`.work/secrets/scram-credentials.p12`). The broker stays plaintext and
   credential-free. SASL termination does not support PLAIN, so the demo uses
   SCRAM.
2. **Role enrichment.** `SaslTermination` is configured with this plugin as its
   `subjectBuilder`. After authentication it binds to LDAP as a service account,
   reads the user's `memberOf`, and maps each group DN to a role name with
   `cn=([^,]+),.*`. So `cn=role-a,ou=groups,dc=example,dc=com` becomes
   `Role[role-a]`.
3. **Authorization.** The `Authorization` filter runs the ACL authorizer against
   `config/acl-rules.txt`. The rules import the plugin's `Role` principal type and
   allow `role-a` on `demo-topic`. The file ends with `otherwise deny`, so bob's
   `role-b` is denied.

The SCRAM passwords and the LDAP passwords are independent. SCRAM proves
identity; LDAP only supplies roles for that identity.

## Files

| Path | Purpose |
|---|---|
| `config/kroxylicious-config.yaml.template` | Proxy config; `up.sh` fills in absolute paths |
| `config/acl-rules.txt` | ACL rules (imports `Role`, allows `role-a`) |
| `ldap/data.ldif` | alice, bob, and the `role-a` / `role-b` groups |
| `ldap/memberof-overlay.ldif` | Enables the OpenLDAP `memberof` overlay so `memberOf` is populated |
| `client/alice.properties`, `client/bob.properties` | SCRAM client configs |
| `env.sh` | Versions, ports, container names, helpers |

## Why `--network host`

kroxylicious advertises its own addresses (`localhost:9192`) back to clients, so
clients must resolve `localhost` the same way the proxy does. The Kafka CLI runs
in a throwaway container with `--network host`, sharing the host network, so
`localhost:9192` reaches the proxy and the rewritten broker addresses work.

## Troubleshooting

- Proxy log: `.work/kroxylicious.log`.
- Inspect roles: `podman exec demo-ldap ldapsearch -x -b ou=people,dc=example,dc=com -D cn=admin,dc=example,dc=com -w admin-secret -LLL "(uid=*)" memberOf`
- Port already bound: stop a prior run with `./demo/down.sh`, or override ports
  via `KAFKA_PORT` / `PROXY_PORT` / `LDAP_PORT` before `up.sh`.
