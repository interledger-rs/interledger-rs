#!/bin/bash
# Fixed Outline Installer - Non-interactive Version
set -euo pipefail

# --- MOFIFIED FUNCTIONS FOR AUTOMATION ---

function confirm() {
  # Always returns true to bypass Y/N questions
  return 0
}

function verify_docker_installed() {
  if command_exists docker; then
    return 0
  fi
  
  # Removed the log_error and confirm check to force install
  log_start_step "Docker not found. Installing automatically"
  if ! run_step "Installing Docker" install_docker; then
    log_error "Docker installation failed. Please install it manually."
    exit 1
  fi
  command_exists docker
}

# --- END OF MODIFICATIONS ---

function display_usage() {
  cat <<EOF
Usage: install_server.sh [--hostname <hostname>] [--api-port <port>] [--keys-port <port>]
EOF
}

readonly SENTRY_LOG_FILE=${SENTRY_LOG_FILE:-}
FULL_LOG="$(mktemp -t outline_logXXXXXXXXXX)"
LAST_ERROR="$(mktemp -t outline_last_errorXXXXXXXXXX)"
readonly FULL_LOG LAST_ERROR

function log_command() {
  "$@" > >(tee -a "${FULL_LOG}") 2> >(tee -a "${FULL_LOG}" > "${LAST_ERROR}")
}

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"
  local -r NO_COLOR="\033[0m"
  echo -e "${ERROR_TEXT}$1${NO_COLOR}"
  echo "$1" >> "${FULL_LOG}"
}

function log_start_step() {
  log_for_sentry "$@"
  local -r str="> $*"
  local -ir lineLength=47
  echo -n "${str}"
  local -ir numDots=$(( lineLength - ${#str} - 1 ))
  if (( numDots > 0 )); then
    echo -n " "
    for _ in $(seq 1 "${numDots}"); do echo -n .; done
  fi
  echo -n " "
}

function run_step() {
  local -r msg="$1"
  log_start_step "${msg}"
  shift 1
  if log_command "$@"; then
    echo "OK"
  else
    return 1
  fi
}

function command_exists {
  command -v "$@" &> /dev/null
}

function log_for_sentry() {
  if [[ -n "${SENTRY_LOG_FILE}" ]]; then
    echo "[$(date "+%Y-%m-%d@%H:%M:%S")] install_server.sh" "$@" >> "${SENTRY_LOG_FILE}"
  fi
  echo "$@" >> "${FULL_LOG}"
}

function verify_docker_running() {
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker info 2>&1 >/dev/null)"
  local -ir RET=$?
  if (( RET == 0 )); then
    return 0
  elif [[ "${STDERR_OUTPUT}" == *"Is the docker daemon running"* ]]; then
    start_docker
    return
  fi
  return "${RET}"
}

function fetch() {
  curl --silent --show-error --fail "$@"
}

function install_docker() {
  (
    umask 0022
    fetch https://get.docker.com/ | sh
  ) >&2
}

function start_docker() {
  systemctl enable --now docker.service >&2
}

function docker_container_exists() {
  docker ps -a --format '{{.Names}}'| grep --quiet "^$1$"
}

function remove_shadowbox_container() {
  remove_docker_container "${CONTAINER_NAME}"
}

function remove_watchtower_container() {
  remove_docker_container watchtower
}

function remove_docker_container() {
  docker rm -f "$1" >&2
}

function handle_docker_container_conflict() {
  local -r CONTAINER_NAME="$1"
  # Logic: Just remove and restart if there is a conflict
  if run_step "Removing ${CONTAINER_NAME} container" "remove_${CONTAINER_NAME}_container" ; then
    log_start_step "Restarting ${CONTAINER_NAME}"
    return 0
  fi
  return 1
}

function finish {
  local -ir EXIT_CODE=$?
  if (( EXIT_CODE != 0 )); then
    if [[ -s "${LAST_ERROR}" ]]; then
      log_error "\nLast error: $(< "${LAST_ERROR}")" >&2
    fi
    log_error "\nInstallation failed. Check log: ${FULL_LOG}" >&2
  else
    rm "${FULL_LOG}"
  fi
  rm "${LAST_ERROR}"
}

function get_random_port {
  local -i num=0
  until (( 1024 <= num && num < 65536)); do
    num=$(( RANDOM + (RANDOM % 2) * 32768 ));
  done;
  echo "${num}";
}

function create_persisted_state_dir() {
  readonly STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  mkdir -p "${STATE_DIR}"
  chmod ug+rwx,g+s,o-rwx "${STATE_DIR}"
}

function safe_base64() {
  local url_safe
  url_safe="$(base64 -w 0 - | tr '/+' '_-')"
  echo -n "${url_safe%%=*}"
}

function generate_secret_key() {
  SB_API_PREFIX="$(head -c 16 /dev/urandom | safe_base64)"
  readonly SB_API_PREFIX
}

function generate_certificate() {
  local -r CERTIFICATE_NAME="${STATE_DIR}/shadowbox-selfsigned"
  readonly SB_CERTIFICATE_FILE="${CERTIFICATE_NAME}.crt"
  readonly SB_PRIVATE_KEY_FILE="${CERTIFICATE_NAME}.key"
  declare -a openssl_req_flags=(
    -x509 -nodes -days 36500 -newkey rsa:4096
    -subj "/CN=${PUBLIC_HOSTNAME}"
    -keyout "${SB_PRIVATE_KEY_FILE}" -out "${SB_CERTIFICATE_FILE}"
  )
  openssl req "${openssl_req_flags[@]}" >&2
}

function generate_certificate_fingerprint() {
  local CERT_OPENSSL_FINGERPRINT
  CERT_OPENSSL_FINGERPRINT="$(openssl x509 -in "${SB_CERTIFICATE_FILE}" -noout -sha256 -fingerprint)" || return
  local CERT_HEX_FINGERPRINT
  CERT_HEX_FINGERPRINT="$(echo "${CERT_OPENSSL_FINGERPRINT#*=}" | tr -d :)" || return
  output_config "certSha256:${CERT_HEX_FINGERPRINT}"
}

function join() {
  local IFS="$1"
  shift
  echo "$*"
}

function write_config() {
  local -a config=()
  if (( FLAGS_KEYS_PORT != 0 )); then
    config+=("\"portForNewAccessKeys\": ${FLAGS_KEYS_PORT}")
  fi
  config+=("\"hostname\": \"$(escape_json_string "${PUBLIC_HOSTNAME}")\"")
  echo "{$(join , "${config[@]}")}" > "${STATE_DIR}/shadowbox_server_config.json"
}

function start_shadowbox() {
  local -r START_SCRIPT="${STATE_DIR}/start_container.sh"
  cat <<-EOF > "${START_SCRIPT}"
set -eu
docker stop "${CONTAINER_NAME}" 2> /dev/null || true
docker rm -f "${CONTAINER_NAME}" 2> /dev/null || true
docker_command=(
  docker run -d --name "${CONTAINER_NAME}" --restart always --net host
  --label 'com.centurylinklabs.watchtower.enable=true'
  --label 'com.centurylinklabs.watchtower.scope=outline'
  --log-driver local
  -v "${STATE_DIR}:${STATE_DIR}"
  -e "SB_STATE_DIR=${STATE_DIR}"
  -e "SB_API_PORT=${API_PORT}"
  -e "SB_API_PREFIX=${SB_API_PREFIX}"
  -e "SB_CERTIFICATE_FILE=${SB_CERTIFICATE_FILE}"
  -e "SB_PRIVATE_KEY_FILE=${SB_PRIVATE_KEY_FILE}"
  "${SB_IMAGE}"
)
"\${docker_command[@]}"
EOF
  chmod +x "${START_SCRIPT}"
  local STDERR_OUTPUT
  STDERR_OUTPUT="$({ "${START_SCRIPT}" >/dev/null; } 2>&1)" && return
  if docker_container_exists "${CONTAINER_NAME}"; then
    handle_docker_container_conflict "${CONTAINER_NAME}"
    return
  fi
}

function start_watchtower() {
  local -ir WATCHTOWER_REFRESH_SECONDS="${WATCHTOWER_REFRESH_SECONDS:-3600}"
  local -ar docker_watchtower_flags=(--name watchtower --log-driver local --restart always \
      --label 'com.centurylinklabs.watchtower.enable=true' \
      --label 'com.centurylinklabs.watchtower.scope=outline' \
      -v /var/run/docker.sock:/var/run/docker.sock)
  docker run -d "${docker_watchtower_flags[@]}" containrrr/watchtower --cleanup --label-enable --scope=outline --tlsverify --interval "${WATCHTOWER_REFRESH_SECONDS}" >/dev/null 2>&1 || true
}

function wait_shadowbox() {
  until fetch --insecure "${LOCAL_API_URL}/access-keys" >/dev/null 2>&1; do sleep 1; done
}

function create_first_user() {
  fetch --insecure --request POST "${LOCAL_API_URL}/access-keys" >&2
}

function output_config() {
  echo "$@" >> "${ACCESS_CONFIG}"
}

function add_api_url_to_config() {
  output_config "apiUrl:${PUBLIC_API_URL}"
}

function check_firewall() {
  # This part stays informative and doesn't require input
  local -i ACCESS_KEY_PORT
  ACCESS_KEY_PORT=$(fetch --insecure "${LOCAL_API_URL}/access-keys" |
      docker exec -i "${CONTAINER_NAME}" node -e '
          const fs = require("fs");
          const accessKeys = JSON.parse(fs.readFileSync(0, {encoding: "utf-8"}));
          console.log(accessKeys["accessKeys"][0]["port"]);
      ') || return
  readonly ACCESS_KEY_PORT
  FIREWALL_STATUS="Make sure to open ports: Management ${API_PORT} (TCP) and Access ${ACCESS_KEY_PORT} (TCP/UDP)"
}

function set_hostname() {
  local -ar urls=('https://icanhazip.com/' 'https://ipinfo.io/ip')
  for url in "${urls[@]}"; do
    PUBLIC_HOSTNAME="$(fetch --ipv4 "${url}")" && return
  done
  return 1
}

function install_shadowbox() {
  umask 0007
  export CONTAINER_NAME="${CONTAINER_NAME:-shadowbox}"
  run_step "Verifying Docker" verify_docker_installed
  run_step "Starting Docker" verify_docker_running
  export SHADOWBOX_DIR="${SHADOWBOX_DIR:-/opt/outline}"
  mkdir -p "${SHADOWBOX_DIR}"
  API_PORT="${FLAGS_API_PORT}"
  if (( API_PORT == 0 )); then API_PORT=${SB_API_PORT:-$(get_random_port)}; fi
  readonly API_PORT
  readonly ACCESS_CONFIG="${ACCESS_CONFIG:-${SHADOWBOX_DIR}/access.txt}"
  readonly SB_IMAGE="${SB_IMAGE:-quay.io/outline/shadowbox:stable}"
  PUBLIC_HOSTNAME="${FLAGS_HOSTNAME:-${SB_PUBLIC_IP:-}}"
  if [[ -z "${PUBLIC_HOSTNAME}" ]]; then run_step "Setting IP" set_hostname; fi
  readonly PUBLIC_HOSTNAME
  if [[ -s "${ACCESS_CONFIG}" ]]; then cp "${ACCESS_CONFIG}" "${ACCESS_CONFIG}.bak" && true > "${ACCESS_CONFIG}"; fi
  run_step "Creating state dir" create_persisted_state_dir
  run_step "Generating key" generate_secret_key
  run_step "Generating cert" generate_certificate
  run_step "Fingerprinting" generate_certificate_fingerprint
  run_step "Writing config" write_config
  run_step "Starting Shadowbox" start_shadowbox
  run_step "Starting Watchtower" start_watchtower
  readonly PUBLIC_API_URL="https://${PUBLIC_HOSTNAME}:${API_PORT}/${SB_API_PREFIX}"
  readonly LOCAL_API_URL="https://localhost:${API_PORT}/${SB_API_PREFIX}"
  run_step "Waiting for health" wait_shadowbox
  run_step "Creating user" create_first_user
  run_step "Finalizing config" add_api_url_to_config
  
  function get_field_value { grep "$1" "${ACCESS_CONFIG}" | sed "s/$1://"; }
  
  echo -e "\n\033[1;32m{\"apiUrl\":\"$(get_field_value apiUrl)\",\"certSha256\":\"$(get_field_value certSha256)\"}\033[0m\n"
}

function is_valid_port() { (( 0 < "$1" && "$1" <= 65535 )); }

function escape_json_string() { echo -n "${1//\"/\\\"}"; }

function parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hostname) FLAGS_HOSTNAME="$2"; shift 2 ;;
      --api-port) FLAGS_API_PORT="$2"; shift 2 ;;
      --keys-port) FLAGS_KEYS_PORT="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
}

function main() {
  trap finish EXIT
  declare FLAGS_HOSTNAME=""
  declare -i FLAGS_API_PORT=0
  declare -i FLAGS_KEYS_PORT=0
  parse_flags "$@"
  install_shadowbox
}

main "$@"
