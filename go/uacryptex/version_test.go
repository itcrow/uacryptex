package uacryptex_test

import (
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

func TestLibraryVersion(t *testing.T) {
	v, err := uacryptex.LibraryVersion()
	if err != nil {
		t.Fatalf("LibraryVersion: %v", err)
	}
	if v != uacryptex.Version {
		t.Fatalf("got version %q, want %q", v, uacryptex.Version)
	}
}
