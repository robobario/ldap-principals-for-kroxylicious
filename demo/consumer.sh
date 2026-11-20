#!/usr/bin/env bash
# Interactive console consumer for a demo user. Follows the topic live.
#   ./demo/consumer.sh alice
# Reads from the beginning with a fresh group each run, then tails. Ctrl-C to quit.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

USER_NAME="${1:-}"
[ -n "${USER_NAME}" ] || die "usage: $(basename "$0") <user>   (e.g. alice, bob)"
[ -f "${DEMO_DIR}/client/${USER_NAME}.properties" ] || die "no client config for '${USER_NAME}' (demo/client/${USER_NAME}.properties)"

say "consumer for '${USER_NAME}' <- ${TOPIC} (Ctrl-C to quit)"
exec "${CONTAINER_ENGINE}" run --rm -it --network host -v "${DEMO_DIR}/client:/client:z" "${KAFKA_IMAGE}" \
  /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server "${PROXY_BOOTSTRAP}" --topic "${TOPIC}" \
  --from-beginning --command-config "/client/${USER_NAME}.properties" \
  --group "${USER_NAME}-interactive-$$-$(date +%s)"
