package uacryptex_test

import (
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

func TestOpenPKCS12IIT(t *testing.T) {
	ks, err := uacryptex.OpenPKCS12(readTestdata(t, "storage", "pkcs12_by_iit.pfx"), "123456")
	if err != nil {
		t.Fatalf("OpenPKCS12: %v", err)
	}
	defer ks.Close()

	key := ks.PrivateKey()
	if key == nil {
		t.Fatal("PrivateKey returned nil")
	}
}
