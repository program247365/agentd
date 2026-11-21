.DEFAULT_GOAL := help
.PHONY: help check fmt test build install

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

check: ## Everything CI would run: format, lint (warnings fail), tests
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

fmt: ## Apply rustfmt
	cargo fmt

test: ## Unit + integration tests (integration needs dolt)
	cargo test

build: ## Release binary at target/release/agentd
	cargo build --release

install: ## cargo install into ~/.cargo/bin
	cargo install --path .
