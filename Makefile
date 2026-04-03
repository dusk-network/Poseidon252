help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run tests (--all-features, release mode)
	@cargo test --all-features --release
	@cargo test --features=encryption --no-run

clippy: ## Run clippy
	@cargo clippy --all-features -- -D warnings
	@cargo clippy --no-default-features -- -D warnings

cq: ## Run code quality checks (formatting + clippy)
	@$(MAKE) fmt CHECK=1
	@$(MAKE) clippy

fmt: ## Format code
	@rustup component add --toolchain nightly rustfmt 2>/dev/null || true
	@cargo +nightly fmt --all $(if $(CHECK),-- --check,)

check: ## Type-check
	@cargo check --all-features

doc: ## Generate docs
	@cargo doc --no-deps --all-features

clean: ## Clean build artifacts
	@cargo clean

no-std: ## Verify no_std bare-metal build
	@rustup target add thumbv6m-none-eabi 2>/dev/null || true
	@cargo build --release --no-default-features --target thumbv6m-none-eabi

.PHONY: help test clippy cq fmt check doc clean no-std
