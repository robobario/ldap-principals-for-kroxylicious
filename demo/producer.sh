#!/usr/bin/env bash
# Interactive console producer for a demo user.
#   ./demo/producer.sh alice
# Type a record per line, press Enter to send, Ctrl-D (or Ctrl-C) to quit.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

USER_NAME="${1:-}"
[ -n "${USER_NAME}" ] || die "usage: $(basename "$0") <user>   (e.g. alice, bob)"
[ -f "${DEMO_DIR}/client/${USER_NAME}.properties" ] || die "no client config for '${USER_NAME}' (demo/client/${USER_NAME}.properties)"

say "producer for '${USER_NAME}' -> ${TOPIC} (type records, Ctrl-D to quit)"
exec "${CONTAINER_ENGINE}" run --rm -it --network host -v "${DEMO_DIR}/client:/client:z" "${KAFKA_IMAGE}" \
  /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server "${PROXY_BOOTSTRAP}" --topic "${TOPIC}" \
  --command-config "/client/${USER_NAME}.properties" \
  --command-property enable.idempotence=false --command-property acks=1
