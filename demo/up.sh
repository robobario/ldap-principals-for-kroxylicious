#!/usr/bin/env bash
# Brings up the whole demo: Kafka, LDAP (alice/bob + groups), the kroxylicious
# install with the LDAP plugin, SCRAM credentials, and the proxy itself.
# Idempotent: safe to re-run.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

command -v "${CONTAINER_ENGINE}" >/dev/null || die "${CONTAINER_ENGINE} not found (set CONTAINER_ENGINE to override)"
command -v gh >/dev/null || die "gh (GitHub CLI) not found; needed to download releases"

container_running() { "${CONTAINER_ENGINE}" inspect "$1" >/dev/null 2>&1; }

mkdir -p "${WORK}/secrets"

# ---------------------------------------------------------------------------
say "Downloading kroxylicious ${KROX_VERSION}"
KROX_ZIP="${WORK}/kroxylicious-app-${KROX_VERSION}-bin.zip"
if [ ! -d "${KROX_HOME}" ]; then
  [ -f "${KROX_ZIP}" ] || gh release download "v${KROX_VERSION}" --repo kroxylicious/kroxylicious \
    --pattern "kroxylicious-app-${KROX_VERSION}-bin.zip" --dir "${WORK}"
  unzip -q -o "${KROX_ZIP}" -d "${WORK}"
fi

PLUGIN_DIR="${KROX_HOME}/classpath-plugins/ldap-principals"
mkdir -p "${KROX_HOME}/classpath-plugins"
if [ "${PLUGIN_SOURCE}" = "local" ]; then
  say "Building the LDAP plugin from this checkout (PLUGIN_SOURCE=local)"
  command -v mvn >/dev/null || die "mvn not found; needed for PLUGIN_SOURCE=local"
  MVN_LOG="$(mktemp /tmp/demo-plugin-build-XXXXXX.log)"
  if ! ( cd "${REPO_ROOT}" && mvn -q -DskipTests clean package ) >"${MVN_LOG}" 2>&1; then
    tail -30 "${MVN_LOG}"; die "plugin build failed, see ${MVN_LOG}"
  fi
  PLUGIN_ZIP="$(ls -t "${REPO_ROOT}"/target/*-distribution.zip 2>/dev/null | head -1)"
  [ -n "${PLUGIN_ZIP}" ] || die "no distribution zip under ${REPO_ROOT}/target (build the assembly?)"
  rm -rf "${PLUGIN_DIR}"
  unzip -q -o "${PLUGIN_ZIP}" -d "${KROX_HOME}/classpath-plugins"
  echo "installed plugin from local build: ${PLUGIN_ZIP}"
elif [ ! -d "${PLUGIN_DIR}" ]; then
  say "Downloading the LDAP plugin ${PLUGIN_VERSION}"
  PLUGIN_ZIP="${WORK}/ldap-principals-${PLUGIN_VERSION}-distribution.zip"
  [ -f "${PLUGIN_ZIP}" ] || gh release download "v${PLUGIN_VERSION}" --repo "${PLUGIN_REPO}" \
    --pattern "*-${PLUGIN_VERSION}-distribution.zip" --output "${PLUGIN_ZIP}"
  unzip -q -o "${PLUGIN_ZIP}" -d "${KROX_HOME}/classpath-plugins"
fi

# ---------------------------------------------------------------------------
say "Starting Kafka (${KAFKA_IMAGE})"
if ! container_running "${KAFKA_CONTAINER}"; then
  "${CONTAINER_ENGINE}" run -d --name "${KAFKA_CONTAINER}" -p "${KAFKA_PORT}:9092" "${KAFKA_IMAGE}" >/dev/null
fi
wait_for "kafka" 60 "${CONTAINER_ENGINE}" exec "${KAFKA_CONTAINER}" \
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

say "Creating topic '${TOPIC}'"
"${CONTAINER_ENGINE}" exec "${KAFKA_CONTAINER}" /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic "${TOPIC}" --partitions 1 --replication-factor 1 >/dev/null

# ---------------------------------------------------------------------------
say "Starting LDAP (${LDAP_IMAGE})"
if ! container_running "${LDAP_CONTAINER}"; then
  "${CONTAINER_ENGINE}" run -d --name "${LDAP_CONTAINER}" \
    -e LDAP_ORGANISATION="Demo" -e LDAP_DOMAIN="example.com" \
    -e LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PW}" \
    -p "${LDAP_PORT}:389" "${LDAP_IMAGE}" >/dev/null
fi
wait_for "ldap" 60 "${CONTAINER_ENGINE}" exec "${LDAP_CONTAINER}" \
  ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PW}"

say "Enabling memberOf overlay and loading users/groups"
# rc 68 == entry already exists, so re-running up.sh is a no-op here.
"${CONTAINER_ENGINE}" exec -i "${LDAP_CONTAINER}" ldapadd -Y EXTERNAL -H ldapi:/// \
  < "${DEMO_DIR}/ldap/memberof-overlay.ldif" >/dev/null 2>&1 || [ $? -eq 68 ]
"${CONTAINER_ENGINE}" exec -i "${LDAP_CONTAINER}" ldapadd -x -H ldap://localhost -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PW}" \
  < "${DEMO_DIR}/ldap/data.ldif" >/dev/null 2>&1 || [ $? -eq 68 ]

echo "LDAP group membership:"
"${CONTAINER_ENGINE}" exec "${LDAP_CONTAINER}" ldapsearch -x -H ldap://localhost -b "ou=people,dc=example,dc=com" \
  -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PW}" -LLL "(uid=*)" uid memberOf

# ---------------------------------------------------------------------------
say "Generating secrets (bind password, credential-store password, SCRAM users)"
printf '%s' "${LDAP_ADMIN_PW}" > "${WORK}/secrets/ldap-bind.pw"
printf '%s' "${CRED_FILE_PW}"  > "${WORK}/secrets/credstore.pw"

SCRAM_FILE="${WORK}/secrets/scram-credentials.p12"
TOOL="${KROX_HOME}/bin/scram-credential-tool.sh --unlock-insecure-options"
# Insecure -p/-w options keep the demo non-interactive; the tool's warnings about
# them are expected, so stderr is silenced here.
rm -f "${SCRAM_FILE}"
$TOOL create   -f "${SCRAM_FILE}" -p "${CRED_FILE_PW}" >/dev/null 2>&1
$TOOL add-user -f "${SCRAM_FILE}" -p "${CRED_FILE_PW}" -u alice -w alice-secret-2026 -m SCRAM-SHA-256 >/dev/null 2>&1
$TOOL add-user -f "${SCRAM_FILE}" -p "${CRED_FILE_PW}" -u bob   -w bob-secret-2026   -m SCRAM-SHA-256 >/dev/null 2>&1
chmod 600 "${WORK}/secrets/"*

# ---------------------------------------------------------------------------
say "Rendering proxy config"
sed -e "s#__WORK__#${WORK}#g" \
    -e "s#__DEMO__#${DEMO_DIR}#g" \
    -e "s#__KAFKA_BOOTSTRAP__#${KAFKA_BOOTSTRAP}#g" \
    -e "s#__PROXY_BOOTSTRAP__#${PROXY_BOOTSTRAP}#g" \
    -e "s#__LDAP_HOSTPORT__#${LDAP_HOSTPORT}#g" \
    "${DEMO_DIR}/config/kroxylicious-config.yaml.template" > "${WORK}/kroxylicious-config.yaml"
echo "rendered proxy config: ${WORK}/kroxylicious-config.yaml"

say "Starting kroxylicious"
if [ -f "${WORK}/kroxylicious.pid" ] && kill -0 "$(cat "${WORK}/kroxylicious.pid")" 2>/dev/null; then
  echo "already running (pid $(cat "${WORK}/kroxylicious.pid"))"
else
  nohup bash "${KROX_HOME}/bin/kroxylicious-start.sh" --config "${WORK}/kroxylicious-config.yaml" \
    > "${WORK}/kroxylicious.log" 2>&1 &
  echo $! > "${WORK}/kroxylicious.pid"
  wait_for "kroxylicious" 60 bash -c "grep -q 'Kroxylicious is started' '${WORK}/kroxylicious.log'"
  echo "started (pid $(cat "${WORK}/kroxylicious.pid")), log: ${WORK}/kroxylicious.log"
fi

say "Up. Run ./demo/test.sh to prove the authorization behaviour."
