package uacryptex_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

func TestSignCMSRoundtrip(t *testing.T) {
	key, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	defer key.Close()

	data := bytes.Repeat([]byte{0xf0}, 100)
	cms, err := uacryptex.SignCMS(data, key)
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}
	if len(cms) == 0 {
		t.Fatal("SignCMS returned empty CMS")
	}
	if err := uacryptex.VerifyCMS(data, cms); err != nil {
		t.Fatalf("VerifyCMS: %v", err)
	}
}

func TestVerifyCMSRejectsTamperedData(t *testing.T) {
	key, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	defer key.Close()

	data := []byte("original")
	cms, err := uacryptex.SignCMS(data, key)
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}
	err = uacryptex.VerifyCMS([]byte("tampered"), cms)
	if err == nil {
		t.Fatal("expected verification error for tampered data")
	}
	if !errors.Is(err, uacryptex.ErrVerifyFailed) {
		t.Fatalf("VerifyCMS error = %v, want ErrVerifyFailed", err)
	}
}
