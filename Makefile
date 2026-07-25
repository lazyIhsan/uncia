.PHONY: test check localstack-up localstack-down localstack-status help

UNCIA_TEST_ENDPOINT ?= http://localhost:4566
QUADLET_DIR := $(HOME)/.config/containers/systemd

help:
	@echo "test            - full offline suite (no container runtime needed)"
	@echo "check           - fmt + clippy + test, as CI runs them"
	@echo "localstack-up   - start LocalStack (podman quadlet if available, else docker)"
	@echo "localstack-down - stop it"

test:
	cargo test --all-targets

check:
	cargo fmt --all --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

# Prefers rootless podman + systemd; falls back to docker compose where there
# is no user systemd session (CI). The tests don't care which one won.
localstack-up:
	@if command -v podman >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then \
		echo "==> podman quadlet"; \
		mkdir -p $(QUADLET_DIR); \
		cp infra/uncia-localstack.container $(QUADLET_DIR)/; \
		systemctl --user daemon-reload; \
		systemctl --user start uncia-localstack; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "==> docker compose"; \
		docker compose -f infra/docker-compose.yml up -d --wait; \
	else \
		echo "no podman(+systemd) or docker available" >&2; exit 1; \
	fi
	@echo "LocalStack on $(UNCIA_TEST_ENDPOINT)"

localstack-down:
	-@systemctl --user stop uncia-localstack 2>/dev/null || true
	-@docker compose -f infra/docker-compose.yml down 2>/dev/null || true

localstack-status:
	@curl -fsS $(UNCIA_TEST_ENDPOINT)/_localstack/health || echo "not reachable"
