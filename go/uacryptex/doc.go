// Package uacryptex provides Ukrainian cryptographic operations for Go applications.
//
// Module: github.com/itcrow/uacryptex
//
// The implementation is backed by the pure Rust uacryptex core, exposed through
// a stable C ABI (uacryptex-ffi). Requires CGO_ENABLED=1 and a prebuilt native
// library — see repository scripts/build-ffi.sh.
//
// User guide (all client languages): https://github.com/itcrow/uacryptex/blob/main/docs/CLIENT_LIBRARIES.md
package uacryptex

// Version matches uacryptex-core Rust crate semver.
const Version = "0.1.0"
