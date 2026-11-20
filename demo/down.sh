#!/usr/bin/env bash
# Tears down the demo: stops the proxy and removes the containers.
# Keeps ./.work (downloads, secrets) unless you pass --purge.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

if [ -f "${WORK}/kroxylicious.pid" ]; then
  pid="$(cat "${WORK}/kroxylicious.pid")"
  kill "${pid}" 2>/dev/null && echo "stopped kroxylicious (pid ${pid})"
  rm -f "${WORK}/kroxylicious.pid"
fi

podman rm -f "${KAFKA_CONTAINER}" "${LDAP_CONTAINER}" >/dev/null 2>&1 && echo "removed containers"

if [ "${1:-}" = "--purge" ]; then
  rm -rf "${WORK}"
  echo "purged ${WORK}"
fi
