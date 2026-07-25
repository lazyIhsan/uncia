#!/usr/bin/env bash
#
# Start/stop LocalStack for uncia's integration tests.
#
#   scripts/localstack.sh up|down|status
#
# Two container runtimes are supported because they win in different places:
#
#   podman quadlet  local work — rootless, so no root-owned daemon and no
#                   `docker` group (which is effectively root). Matches uncia's
#                   own argument that a drift detector shouldn't require
#                   privileged agents. `Notify=healthy` in the unit makes
#                   systemd report the service started only once LocalStack is
#                   actually healthy, so tests can't race startup.
#   docker compose  CI and anywhere without a systemd user session, where
#                   `systemctl --user` has no dbus session to attach to.
#
# `up` prefers podman and falls back to docker. Nothing else in the test suite
# depends on which one won: tests only require that something answers on
# UNCIA_TEST_ENDPOINT.

set -euo pipefail

ENDPOINT="${UNCIA_TEST_ENDPOINT:-http://localhost:4566}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUADLET_DIR="${HOME}/.config/containers/systemd"
UNIT="uncia-localstack"

have_podman() {
    command -v podman >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1
}

have_docker() {
    command -v docker >/dev/null 2>&1
}

up() {
    if have_podman; then
        echo "==> podman quadlet (rootless)"
        mkdir -p "$QUADLET_DIR"
        cp "$REPO_ROOT/infra/${UNIT}.container" "$QUADLET_DIR/"
        systemctl --user daemon-reload
        systemctl --user start "$UNIT"
    elif have_docker; then
        echo "==> docker compose"
        docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d --wait
    else
        echo "need either podman with a systemd user session, or docker" >&2
        exit 1
    fi
    echo "LocalStack on ${ENDPOINT}"
}

down() {
    # Both are attempted: whichever runtime brought it up, this tears it down,
    # and the other simply has nothing to stop.
    systemctl --user stop "$UNIT" 2>/dev/null || true
    docker compose -f "$REPO_ROOT/infra/docker-compose.yml" down 2>/dev/null || true
    echo "stopped"
}

status() {
    if curl -fsS "${ENDPOINT}/_localstack/health"; then
        echo
    else
        echo "not reachable at ${ENDPOINT}" >&2
        exit 1
    fi
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *)
        echo "usage: $(basename "$0") up|down|status" >&2
        exit 2
        ;;
esac
