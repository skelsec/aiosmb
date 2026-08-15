#!/bin/sh
set -eu

lab_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${lab_directory}/../../.." && pwd)
compose_file="${lab_directory}/compose.yml"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    docker compose -f "$compose_file" down --volumes --remove-orphans \
        >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT INT TERM

export AIOSMB_SAMBA_PROFILE="${AIOSMB_SAMBA_PROFILE:-${lab_directory}/profile.example.yml}"

docker compose -f "$compose_file" up --build --detach --wait --wait-timeout 90

echo "Container Samba version:"
docker compose -f "$compose_file" exec -T samba smbd --version
docker compose -f "$compose_file" exec -T samba \
    dpkg-query -W -f='${Package}=${Version}\n' samba

cd "$repository_root"
"${PYTHON:-python3}" -m pytest tests/interop/samba \
    --run-samba \
    --run-destructive \
    --run-slow \
    --capability protocol_probe \
    --capability ntlm \
    --capability signing_observation \
    --capability directory_crud \
    --capability file_crud \
    --capability large_transfer \
    --capability concurrency \
    --capability srvsvc \
    --capability security_descriptor \
    "$@"
