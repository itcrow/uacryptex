package uacryptex_test

import (
	"bytes"
	"testing"

	"github.com/itcrow/uacryptex/uacryptex"
)

func TestEnvelopCMSRoundtrip(t *testing.T) {
	originator, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey originator: %v", err)
	}
	defer originator.Close()

	recipient, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "userur_private_key.dat"),
		readTestdata(t, "pki", "pki_example", "userur_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey recipient: %v", err)
	}
	defer recipient.Close()

	recipientCert := readTestdata(t, "pki", "pki_example", "userur_certificate.cer")
	plaintext := []byte("Status message for enveloped data test")

	cms, err := uacryptex.EnvelopCMS(plaintext, originator, recipientCert)
	if err != nil {
		t.Fatalf("EnvelopCMS: %v", err)
	}
	if len(cms) == 0 {
		t.Fatal("EnvelopCMS returned empty CMS")
	}

	decrypted, err := uacryptex.DecryptCMS(cms, recipient, recipientCert, nil, nil)
	if err != nil {
		t.Fatalf("DecryptCMS: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptCMS = %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopCMSKalyna256GCMRoundtrip(t *testing.T) {
	originator, recipient, recipientCert, plaintext := envelopTestFixtures(t)

	cms, err := uacryptex.EnvelopCMSWithCipher(
		plaintext, originator, recipientCert, uacryptex.ContentCipherKalyna256GCM,
	)
	if err != nil {
		t.Fatalf("EnvelopCMSWithCipher: %v", err)
	}

	decrypted, err := uacryptex.DecryptCMS(cms, recipient, recipientCert, nil, nil)
	if err != nil {
		t.Fatalf("DecryptCMS: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptCMS = %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopCMSKalyna128GCMRoundtrip(t *testing.T) {
	originator, recipient, recipientCert, plaintext := envelopTestFixtures(t)

	cms, err := uacryptex.EnvelopCMSWithCipher(
		plaintext, originator, recipientCert, uacryptex.ContentCipherKalyna128GCM,
	)
	if err != nil {
		t.Fatalf("EnvelopCMSWithCipher: %v", err)
	}

	decrypted, err := uacryptex.DecryptCMS(cms, recipient, recipientCert, nil, nil)
	if err != nil {
		t.Fatalf("DecryptCMS: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptCMS = %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopCMSKalyna512GCMRoundtrip(t *testing.T) {
	originator, recipient, recipientCert, plaintext := envelopTestFixtures(t)

	cms, err := uacryptex.EnvelopCMSWithCipher(
		plaintext, originator, recipientCert, uacryptex.ContentCipherKalyna512GCM,
	)
	if err != nil {
		t.Fatalf("EnvelopCMSWithCipher: %v", err)
	}

	decrypted, err := uacryptex.DecryptCMS(cms, recipient, recipientCert, nil, nil)
	if err != nil {
		t.Fatalf("DecryptCMS: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptCMS = %q, want %q", decrypted, plaintext)
	}
}

func envelopTestFixtures(t *testing.T) (*uacryptex.PrivateKey, *uacryptex.PrivateKey, []byte, []byte) {
	t.Helper()
	originator, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(t, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey originator: %v", err)
	}
	t.Cleanup(func() { originator.Close() })

	recipient, err := uacryptex.OpenPrivateKey(
		readTestdata(t, "pki", "userur_private_key.dat"),
		readTestdata(t, "pki", "pki_example", "userur_certificate.cer"),
	)
	if err != nil {
		t.Fatalf("OpenPrivateKey recipient: %v", err)
	}
	t.Cleanup(func() { recipient.Close() })

	recipientCert := readTestdata(t, "pki", "pki_example", "userur_certificate.cer")
	plaintext := []byte("Status message for enveloped data test")
	return originator, recipient, recipientCert, plaintext
}
