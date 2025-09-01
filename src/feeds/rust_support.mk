RUST_BUILD_MODE ?= release

RUST_CARGO      ?= cargo
RUST_RUSTUP     ?= rustup

RUST_SCAN_DIR   := Rust/feeds
RUST_MODE_FLAG  := $(if $(filter $(RUST_BUILD_MODE),release),--release,)

CARGO_PRESENT  := false
RUSTUP_PRESENT := false

CARGO_VERSION := $(word 2, $(shell $(RUST_CARGO) version 2>/dev/null))
ifneq ($(filter 1.%,$(CARGO_VERSION)),)
	CARGO_PRESENT := true
endif

RUSTUP_VERSION := $(word 2, $(shell $(RUST_RUSTUP) --version 2>/dev/null))
ifneq ($(filter 1.%,$(RUSTUP_VERSION)),)
	RUSTUP_PRESENT := true
endif

ifeq ($(CARGO_PRESENT),true)

ifeq ($(shell uname),Darwin)
	RUST_LIB_EXT = dylib
else
	RUST_LIB_EXT = so
endif

feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^
	cp Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	$(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^ --target x86_64-pc-windows-gnu
	cp Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
else
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: rustup not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
endif
else
feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: cargo not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: cargo not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
endif

FEEDS_RUST_SRC := $(wildcard $(RUST_SCAN_DIR)/*/Cargo.toml)

ifeq ($(BUILD_MODE),cross)
feeds_linux: $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.so,  $(FEEDS_RUST_SRC))
feeds_win:   $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.dll, $(FEEDS_RUST_SRC))
else
feeds: $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.$(FEEDS_SUFFIX), $(FEEDS_RUST_SRC))
endif

