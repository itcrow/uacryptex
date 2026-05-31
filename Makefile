.PHONY: test build-ffi build-ffi-all sync-native-libs build-client-libs sync-version verify-version prepare-release sync-header go-test python-test php-test node-test api-inventory mvp certification

test:
	cargo test --workspace

build-ffi:
	./scripts/build-ffi.sh

build-ffi-all:
	./scripts/build-ffi-all.sh

sync-native-libs:
	./scripts/sync-native-libs.sh

# Build for host + copy into go/python/php/nodejs packages
build-client-libs: build-ffi sync-native-libs

sync-version:
	./scripts/sync-version.sh

verify-version:
	./scripts/verify-version.sh

prepare-release:
	./scripts/prepare-release.sh

sync-header:
	./scripts/sync-header.sh

go-test: build-client-libs
	cd go && CGO_ENABLED=1 go test ./...

python-test: build-client-libs
	cd python && pip install -e . -q && python tests/test_version.py

php-test: build-client-libs
	cd php && php -d ffi.enable=1 tests/VersionTest.php

node-test: build-client-libs
	cd nodejs && npm install -q && npm test

mvp: build-client-libs
	cargo test -p uacryptex-core --test pki_example
	cd go && CGO_ENABLED=1 go test -run TestMVP ./...

certification: test mvp
	@echo "Certification smoke OK (full matrix: docs/CERTIFICATION.md)"

api-inventory:
	./scripts/generate-api-inventory.sh
