package uacryptex_test

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

func TestPrivateKeyImplementsSigner(t *testing.T) {
	key, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	defer key.Close()

	var signer crypto.Signer = key
	if signer.Public() != nil {
		t.Log("Public key not yet exposed for DSTU4145")
	}

	digest := make([]byte, 32)
	digest[31] = 1
	sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}
