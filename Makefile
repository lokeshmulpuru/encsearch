# Thin wrapper so `make && make install` (what the pgxn client runs) works.
# Requires Rust and cargo-pgrx; see README.md.
PG_CONFIG ?= pg_config
PG_MAJOR = $(shell $(PG_CONFIG) --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
VERSION := $(shell grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.*)"/\1/')

.PHONY: all install test dist clean

all:
	cargo pgrx package --pg-config $(PG_CONFIG) --no-default-features --features pg$(PG_MAJOR)

install:
	cargo pgrx install --release --pg-config $(PG_CONFIG) --no-default-features --features pg$(PG_MAJOR)

test:
	cargo pgrx test pg$(PG_MAJOR)

# Source zip for PGXN upload.
dist:
	mkdir -p dist
	git archive --format zip --prefix=encsearch-$(VERSION)/ -o dist/encsearch-$(VERSION).zip HEAD

clean:
	cargo clean
	rm -rf dist
