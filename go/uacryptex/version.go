package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// LibraryVersion returns the Rust core version string.
func LibraryVersion() (string, error) {
	return native.Version()
}
