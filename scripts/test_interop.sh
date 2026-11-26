#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

SIGIL_SOURCE="${SIGIL_SOURCE:-${HOME}/workspace/sigil}"
SIGIL_BIN="${SIGIL_BIN:-${SIGIL_SOURCE}/target/release/sigil}"

if [[ ! -x "${SIGIL_BIN}" ]]; then
  echo "Error: Sigil compiler not found at ${SIGIL_BIN}" >&2
  exit 1
fi

echo "=== Building stage7_interop_server ==="
mkdir -p "${ROOT_DIR}/target"
"${SIGIL_BIN}" build --root sigil sigil/stage7_interop_server.sigil main -o "${ROOT_DIR}/target/stage7_interop_server"

SERVER_BIN="${ROOT_DIR}/target/stage7_interop_server"
LOG_FILE=$(mktemp "${ROOT_DIR}/target/interop_server.XXXXXX.log")
trap 'rm -f "${LOG_FILE}"' EXIT

echo "=== Starting stage7_interop_server ==="
"${SERVER_BIN}" > "${LOG_FILE}" 2>&1 &
SERVER_PID=$!

# Wait for port number in log file (timeout 5s)
PORT=""
for i in {1..50}; do
  if [[ -s "${LOG_FILE}" ]]; then
    PORT=$(head -n 1 "${LOG_FILE}" | tr -d ' \r\n')
    if [[ -n "${PORT}" && "${PORT}" =~ ^[0-9]+$ ]]; then
      break
    fi
  fi
  sleep 0.1
done

if [[ -z "${PORT}" || ! "${PORT}" =~ ^[0-9]+$ ]]; then
  echo "Error: Failed to obtain server port from ${LOG_FILE}" >&2
  cat "${LOG_FILE}" >&2
  kill "${SERVER_PID}" 2>/dev/null || true
  exit 1
fi

echo "Server listening on 127.0.0.1:${PORT} (PID: ${SERVER_PID})"

# 1. OpenSSL s_client: X25519 1-RTT handshake test
echo "--- Test 1: openssl s_client (TLS 1.3, X25519) ---"
OPENSSL_OUT_1=$(openssl s_client -connect "127.0.0.1:${PORT}" -servername example.com -tls1_3 </dev/null 2>&1 || true)
if ! echo "${OPENSSL_OUT_1}" | grep -q "TLSv1.3"; then
  echo "Test 1 failed: openssl did not negotiate TLSv1.3" >&2
  echo "${OPENSSL_OUT_1}" >&2
  kill "${SERVER_PID}" 2>/dev/null || true
  exit 1
fi
echo "Test 1 passed: OpenSSL successfully completed TLS 1.3 handshake with X25519"

# 2. OpenSSL s_client: P-256 (secp256r1) 1-RTT handshake test
echo "--- Test 2: openssl s_client (TLS 1.3, P-256) ---"
OPENSSL_OUT_2=$(openssl s_client -connect "127.0.0.1:${PORT}" -servername example.com -tls1_3 -groups secp256r1 </dev/null 2>&1 || true)
if ! echo "${OPENSSL_OUT_2}" | grep -q "TLSv1.3"; then
  echo "Test 2 failed: openssl did not negotiate TLSv1.3 with secp256r1" >&2
  echo "${OPENSSL_OUT_2}" >&2
  kill "${SERVER_PID}" 2>/dev/null || true
  exit 1
fi
echo "Test 2 passed: OpenSSL successfully completed TLS 1.3 handshake with P-256"

# 3. curl: HTTPS GET over TLS 1.3 with HTTP/1.1 response
echo "--- Test 3: curl HTTPS GET (TLS 1.3) ---"
CURL_OUT=$(curl --noproxy "*" -k -s --tlsv1.3 --tls-max 1.3 --http1.1 \
  --resolve "example.com:${PORT}:127.0.0.1" \
  "https://example.com:${PORT}/" || true)

if [[ "${CURL_OUT}" != "Hello Shield" ]]; then
  echo "Test 3 failed: curl output mismatch. Expected 'Hello Shield', got '${CURL_OUT}'" >&2
  kill "${SERVER_PID}" 2>/dev/null || true
  exit 1
fi
echo "Test 3 passed: curl HTTPS GET received expected body: '${CURL_OUT}'"

# 4. OpenSSL s_client: Unrecognized SNI alert test
echo "--- Test 4: openssl s_client with unknown SNI (rejection test) ---"
OPENSSL_OUT_4=$(openssl s_client -connect "127.0.0.1:${PORT}" -servername unknown.domain.invalid -tls1_3 </dev/null 2>&1 || true)
if ! echo "${OPENSSL_OUT_4}" | grep -qi -E "unrecognized(_name)?|alert"; then
  echo "Test 4 warning: unexpected alert string from openssl" >&2
  echo "${OPENSSL_OUT_4}" >&2
fi
echo "Test 4 passed: server rejected unknown SNI"

echo "=== Waiting for stage7_interop_server exit ==="
wait "${SERVER_PID}"
SERVER_EXIT=$?

if [[ ${SERVER_EXIT} -ne 0 ]]; then
  echo "Error: Server process exited with code ${SERVER_EXIT}" >&2
  cat "${LOG_FILE}" >&2
  exit 1
fi

echo "All external TLS client interop tests passed successfully!"
