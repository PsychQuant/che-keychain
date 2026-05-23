# Makefile
BINARY_NAME := CheKeychain
INSTALL_NAME := che-keychain

.PHONY: build test release release-signed install clean verify-release-ready

build:
	swift build

test:
	swift test

# Local release build (ad-hoc signed). Dev iteration only — NOT for distribution.
release:
	@./scripts/build-release.sh

# Distribution release: universal arm64+x86_64 binary, Developer ID signed,
# Apple notarized. Requires keychain profile setup — see README.
release-signed: verify-release-ready
	@: $${DEVELOPER_ID:?DEVELOPER_ID not set. See README 'Signing & Notarization'.}
	@: $${NOTARY_PROFILE:?NOTARY_PROFILE not set. See README 'Signing & Notarization'.}
	REQUIRE_CODESIGN=1 ./scripts/build-release.sh

# Local install. che-keychain itself doesn't need TCC, just PATH access.
install: release
	mkdir -p ~/bin
	rm -f ~/bin/$(INSTALL_NAME)
	cp release/$(BINARY_NAME) ~/bin/$(INSTALL_NAME)
	chmod +x ~/bin/$(INSTALL_NAME)
	@echo "Installed: ~/bin/$(INSTALL_NAME)"

# Soft pre-flight: warns on AppVersion vs latest-tag drift, never aborts.
verify-release-ready:
	@SOURCE_VERSION=$$(grep -E 'static let version = "' Sources/CheKeychain/Version.swift | sed -E 's/.*"([^"]+)".*/\1/'); \
	LATEST_TAG=$$(git tag --sort=-creatordate | head -1); \
	if [ -z "$$SOURCE_VERSION" ]; then \
	    echo "✗ Could not parse AppVersion.version from Version.swift" >&2; exit 1; \
	fi; \
	if [ -z "$$LATEST_TAG" ]; then \
	    echo "ℹ No git tags yet — version drift check skipped (first release?)"; \
	elif [ "v$${SOURCE_VERSION}" = "$$LATEST_TAG" ]; then \
	    echo "ℹ AppVersion ($$SOURCE_VERSION) matches latest tag — no bump needed"; \
	elif [ "$$(printf '%s\n%s\n' "v$${SOURCE_VERSION}" "$$LATEST_TAG" | sort -V | tail -1)" = "v$${SOURCE_VERSION}" ]; then \
	    echo "⚠ Pre-release drift: AppVersion=$$SOURCE_VERSION ahead of tag=$$LATEST_TAG (expected if cutting v$${SOURCE_VERSION})"; \
	else \
	    echo "⚠ DOWNGRADE drift: AppVersion=$$SOURCE_VERSION BEHIND tag=$$LATEST_TAG — investigate before tagging"; \
	fi

clean:
	swift package clean
	rm -rf .build release
