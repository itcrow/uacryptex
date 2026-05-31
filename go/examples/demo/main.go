// Demo program for uacryptex Go bindings.
//
// Prerequisites:
//   - CGO_ENABLED=1
//   - Native library built: ../../scripts/build-ffi.sh && ../../scripts/sync-native-libs.sh
//   - Run from repository checkout (uses testdata/pki/pki_example fixtures)
//
// Usage:
//
//	cd go && CGO_ENABLED=1 go run ./examples/demo/
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/itcrow/uacryptex/uacryptex"
)

// fixtureTime is within notBefore/notAfter of testdata/pki/pki_example certificates.
const fixtureTime = int64(1359151200) // 2013-01-25 12:00:00 UTC

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	version, err := uacryptex.LibraryVersion()
	if err != nil {
		return fmt.Errorf("LibraryVersion: %w", err)
	}
	fmt.Printf("uacryptex core %s (Go binding %s)\n\n", version, uacryptex.Version)

	rootCert, err := readTestdata("pki", "pki_example", "root_certificate.cer")
	if err != nil {
		return err
	}
	userKey, err := readTestdata("pki", "pki_example", "userfiz_private_key_ba.dat")
	if err != nil {
		return err
	}
	userCert, err := readTestdata("pki", "pki_example", "userfiz_certificate.cer")
	if err != nil {
		return err
	}
	recipientCert, err := readTestdata("pki", "pki_example", "userur_certificate.cer")
	if err != nil {
		return err
	}
	recipientKey, err := readTestdata("pki", "userur_private_key.dat")
	if err != nil {
		return err
	}
	fullCRL, err := readTestdata("pki", "pki_example", "full.crl")
	if err != nil {
		return err
	}

	// --- 1. Open signing key (raw key bytes + end-entity certificate) ---
	key, err := uacryptex.OpenPrivateKey(userKey, userCert)
	if err != nil {
		return fmt.Errorf("OpenPrivateKey: %w", err)
	}
	defer key.Close()
	fmt.Println("1. OpenPrivateKey — ok")

	// --- 2. Certificate chain checks ---
	if err := uacryptex.VerifyCertificate(userCert, rootCert); err != nil {
		return fmt.Errorf("VerifyCertificate: %w", err)
	}
	if err := uacryptex.CheckCertificateValidity(userCert, fixtureTime); err != nil {
		return fmt.Errorf("CheckCertificateValidity: %w", err)
	}
	fmt.Println("2. VerifyCertificate + CheckCertificateValidity — ok")

	// --- 3. Detached signature via crypto.Signer (32-byte GOST3411 digest) ---
	payload := []byte("Статус повідомлення")
	digest, err := uacryptex.Digest(payload, nil, userCert)
	if err != nil {
		return fmt.Errorf("Digest: %w", err)
	}
	sig, err := key.Sign(rand.Reader, digest, crypto.SignerOpts(nil))
	if err != nil {
		return fmt.Errorf("Sign: %w", err)
	}
	if err := uacryptex.VerifyHash(digest, sig, userCert); err != nil {
		return fmt.Errorf("VerifyHash: %w", err)
	}
	fmt.Printf("3. Digest + crypto.Signer + VerifyHash — ok (%d-byte digest)\n", len(digest))

	// --- 4. CMS SignedData (CAdES-BES subset) ---
	cms, err := uacryptex.SignCMS(payload, key)
	if err != nil {
		return fmt.Errorf("SignCMS: %w", err)
	}
	if err := uacryptex.VerifyCMS(payload, cms); err != nil {
		return fmt.Errorf("VerifyCMS: %w", err)
	}
	fmt.Printf("4. SignCMS + VerifyCMS — ok (%d-byte CMS)\n", len(cms))

	// --- 5. CAdES-T (BES + signature timestamp token) ---
	tsaKey, err := uacryptex.OpenPrivateKey(userKey, userCert)
	if err != nil {
		return fmt.Errorf("OpenPrivateKey (TSA): %w", err)
	}
	defer tsaKey.Close()
	serial := []byte{0x80}
	cadesT, err := uacryptex.SignCmsCadesT(payload, serial, key, tsaKey, fixtureTime, nil)
	if err != nil {
		return fmt.Errorf("SignCmsCadesT: %w", err)
	}
	if err := uacryptex.VerifyCMS(payload, cadesT); err != nil {
		return fmt.Errorf("VerifyCMS (CAdES-T): %w", err)
	}
	fmt.Printf("5. SignCmsCadesT — ok (%d-byte CMS)\n", len(cadesT))

	// --- 6. CAdES-C (certificate + CRL references) ---
	cadesC, err := uacryptex.SignCmsCadesC(payload, rootCert, fullCRL, key)
	if err != nil {
		return fmt.Errorf("SignCmsCadesC: %w", err)
	}
	if err := uacryptex.VerifyCMS(payload, cadesC); err != nil {
		return fmt.Errorf("VerifyCMS (CAdES-C): %w", err)
	}
	fmt.Printf("6. SignCmsCadesC — ok (%d-byte CMS)\n", len(cadesC))

	// --- 7. Enveloped CMS (encrypt for recipient, decrypt with recipient key) ---
	recipient, err := uacryptex.OpenPrivateKey(recipientKey, recipientCert)
	if err != nil {
		return fmt.Errorf("OpenPrivateKey (recipient): %w", err)
	}
	defer recipient.Close()

	enveloped, err := uacryptex.EnvelopCMS(payload, key, recipientCert)
	if err != nil {
		return fmt.Errorf("EnvelopCMS: %w", err)
	}
	plaintext, err := uacryptex.DecryptCMS(enveloped, recipient, recipientCert, nil, nil)
	if err != nil {
		return fmt.Errorf("DecryptCMS: %w", err)
	}
	if !bytes.Equal(plaintext, payload) {
		return fmt.Errorf("DecryptCMS: plaintext mismatch")
	}
	fmt.Printf("7. EnvelopCMS + DecryptCMS — ok (%d-byte enveloped CMS)\n", len(enveloped))

	// --- 8. OCSP request for end-entity certificate ---
	ocspReq, err := uacryptex.OcspRequestFromCert(rootCert, userCert)
	if err != nil {
		return fmt.Errorf("OcspRequestFromCert: %w", err)
	}
	signedOCSP, err := uacryptex.OcspRequestGenerate(rootCert, userCert, key, nil, nil, true)
	if err != nil {
		return fmt.Errorf("OcspRequestGenerate: %w", err)
	}
	fmt.Printf("8. OCSP request — unsigned %d B, signed %d B\n", len(ocspReq), len(signedOCSP))

	// --- 9. PKCS#12 keystore ---
	p12, err := readTestdata("storage", "pkcs12_by_iit.pfx")
	if err != nil {
		return err
	}
	ks, err := uacryptex.OpenPKCS12(p12, "123456")
	if err != nil {
		return fmt.Errorf("OpenPKCS12: %w", err)
	}
	defer ks.Close()
	if ks.PrivateKey() == nil {
		return fmt.Errorf("OpenPKCS12: no private key in keystore")
	}
	count, err := ks.CertificateCount()
	if err != nil {
		return fmt.Errorf("CertificateCount: %w", err)
	}
	fmt.Printf("9. OpenPKCS12 — ok (%d embedded certificate(s))\n", count)

	fmt.Println("\nAll steps passed.")
	return nil
}
