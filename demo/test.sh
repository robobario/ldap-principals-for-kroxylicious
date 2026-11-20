#!/usr/bin/env bash
# Proves the end-to-end behaviour:
#   alice (LDAP group role-a -> Role[role-a]) can produce and consume demo-topic
#   bob   (LDAP group role-b -> Role[role-b]) is denied by the ACL
# Note: no `pipefail` on purpose; `grep -q` closing a pipe early would otherwise
# surface as a SIGPIPE failure of the upstream container command.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

run_client() {
  "${CONTAINER_ENGINE}" run --rm -i --network host -v "${DEMO_DIR}/client:/client:z" "${KAFKA_IMAGE}" "$@"
}

MSG="hello-from-alice-$(date +%s)"
fail=0

say "alice produces to ${TOPIC} (expect SUCCESS)"
out="$(echo "${MSG}" | run_client /opt/kafka/bin/kafka-console-producer.sh \
      --bootstrap-server "${PROXY_BOOTSTRAP}" --topic "${TOPIC}" \
      --command-config /client/alice.properties \
      --command-property enable.idempotence=false --command-property acks=1 2>&1)"
if grep -qi "authorization" <<<"${out}"; then
  echo "UNEXPECTED: alice was denied"; echo "${out}"; fail=1
else
  echo "OK: alice produced"
fi

say "alice consumes from ${TOPIC} (expect to read a record)"
# --max-messages 1 returns on the first record instead of idling out the
# timeout; with the default fetch.min.bytes=1 the broker replies as soon as a
# byte is available. Fresh group so --from-beginning is honoured.
out="$(run_client /opt/kafka/bin/kafka-console-consumer.sh \
      --bootstrap-server "${PROXY_BOOTSTRAP}" --topic "${TOPIC}" \
      --from-beginning --max-messages 1 --timeout-ms 15000 \
      --command-config /client/alice.properties --group "alice-$$-$(date +%s)" 2>&1)"
if grep -qi "authorization" <<<"${out}"; then
  echo "UNEXPECTED: alice was denied"; echo "${out}" | tail -3; fail=1
elif grep -q "Processed a total of 1 messages" <<<"${out}"; then
  echo "OK: alice consumed a record"
else
  echo "UNEXPECTED: alice could not consume a record"; echo "${out}" | tail -3; fail=1
fi

say "bob produces to ${TOPIC} (expect DENIED)"
out="$(echo "hello-from-bob" | run_client /opt/kafka/bin/kafka-console-producer.sh \
      --bootstrap-server "${PROXY_BOOTSTRAP}" --topic "${TOPIC}" \
      --command-config /client/bob.properties \
      --command-property enable.idempotence=false --command-property acks=1 2>&1)"
if grep -qi "TOPIC_AUTHORIZATION_FAILED\|TopicAuthorizationException" <<<"${out}"; then
  echo "OK: bob was denied (TopicAuthorizationException)"
else
  echo "UNEXPECTED: bob was not denied"; echo "${out}" | tail -3; fail=1
fi

if [ "${fail}" -eq 0 ]; then
  say "PASS: role-a allowed, role-b denied"
else
  say "FAIL: see output above"
fi
exit "${fail}"
