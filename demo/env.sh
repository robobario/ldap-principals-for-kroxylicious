# Shared configuration for the demo scripts. Sourced, not executed.

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
WORK="${DEMO_DIR}/.work"

KROX_VERSION="${KROX_VERSION:-0.26.0}"
KROX_HOME="${WORK}/kroxylicious-app-${KROX_VERSION}"
PLUGIN_VERSION="${PLUGIN_VERSION:-0.1.0}"
PLUGIN_REPO="${PLUGIN_REPO:-robobario/ldap-principals-for-kroxylicious}"

# release (default): download the plugin from its GitHub release.
# local: build the plugin from this checkout and use the produced distribution zip.
PLUGIN_SOURCE="${PLUGIN_SOURCE:-release}"

CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"

KAFKA_IMAGE="${KAFKA_IMAGE:-docker.io/apache/kafka:4.4.0}"
LDAP_IMAGE="${LDAP_IMAGE:-docker.io/osixia/openldap:1.5.0}"

KAFKA_CONTAINER="${KAFKA_CONTAINER:-demo-kafka}"
LDAP_CONTAINER="${LDAP_CONTAINER:-demo-ldap}"

# Host ports. The proxy and the kafka client tools run with --network host,
# so every address below is reachable as localhost.
KAFKA_PORT="${KAFKA_PORT:-9092}"
PROXY_PORT="${PROXY_PORT:-9192}"
LDAP_PORT="${LDAP_PORT:-1389}"

KAFKA_BOOTSTRAP="localhost:${KAFKA_PORT}"
PROXY_BOOTSTRAP="localhost:${PROXY_PORT}"
LDAP_HOSTPORT="localhost:${LDAP_PORT}"

TOPIC="${TOPIC:-demo-topic}"

LDAP_ADMIN_DN="cn=admin,dc=example,dc=com"
LDAP_ADMIN_PW="admin-secret"
CRED_FILE_PW="credfilepass123"

say() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

wait_for() {
  # wait_for <description> <seconds> <command...>
  local desc="$1" timeout="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "timed out waiting for ${desc}"
    sleep 1
  done
}
