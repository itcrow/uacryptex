#!/usr/bin/env bash
# Supported uacryptex client-library platforms (GOOS GOARCH).
# Keep in sync with .github/workflows/build-ffi.yml matrix.

UACRYPTEX_PLATFORMS=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)
