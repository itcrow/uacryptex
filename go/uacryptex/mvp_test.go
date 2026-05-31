package uacryptex_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

// TestMVP covers the vertical slice: key open → sign digest → CMS → PKCS#12.
func TestMVP(t *testing.T) {
	key, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	defer key.Close()

	digest := make([]byte, 32)
	digest[31] = 0x01
	if _, err := key.Sign(rand.Reader, digest, crypto.SignerOpts(nil)); err != nil {
		t.Fatalf("Sign digest: %v", err)
	}

	data := bytes.Repeat([]byte{0xf0}, 100)
	cms, err := uacryptex.SignCMS(data, key)
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}
	if err := uacryptex.VerifyCMS(data, cms); err != nil {
		t.Fatalf("VerifyCMS: %v", err)
	}

	ks, err := uacryptex.OpenPKCS12(readTestdata(t, "storage", "pkcs12_by_iit.pfx"), "123456")
	if err != nil {
		t.Fatalf("OpenPKCS12: %v", err)
	}
	defer ks.Close()
	if ks.PrivateKey() == nil {
		t.Fatal("PKCS#12 keystore has no private key")
	}
}
