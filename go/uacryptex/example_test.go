package uacryptex_test

import (
	"bytes"
	"fmt"

	"github.com/itcrow/uacryptex/uacryptex"
)

func ExampleLibraryVersion() {
	v, err := uacryptex.LibraryVersion()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(v == uacryptex.Version)
	// Output: true
}

func ExampleSignCMS() {
	key, err := uacryptex.OpenPrivateKey(
		readTestdata(nil, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(nil, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer key.Close()

	data := bytes.Repeat([]byte{0xf0}, 100)
	cms, err := uacryptex.SignCMS(data, key)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if err := uacryptex.VerifyCMS(data, cms); err != nil {
		fmt.Println("verify failed:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// Example_signDocument signs a file and writes a CMS container (.p7s).
// See go/examples/sign-document/ for a command-line tool.
func Example_signDocument() {
	document := readTestdata(nil, "documents", "sample.txt")

	key, err := uacryptex.OpenPrivateKey(
		readTestdata(nil, "pki", "pki_example", "userfiz_private_key_ba.dat"),
		readTestdata(nil, "pki", "pki_example", "userfiz_certificate.cer"),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer key.Close()

	cms, err := uacryptex.SignCMS(document, key)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if err := uacryptex.VerifyCMS(document, cms); err != nil {
		fmt.Println("verify failed:", err)
		return
	}
	fmt.Println("signed and verified")
	// Output: signed and verified
}

func ExampleOpenPKCS12() {
	ks, err := uacryptex.OpenPKCS12(readTestdata(nil, "storage", "pkcs12_by_iit.pfx"), "123456")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer ks.Close()
	if ks.PrivateKey() == nil {
		fmt.Println("no key")
		return
	}
	fmt.Println("opened")
	// Output: opened
}

// Example_workflow demonstrates the MVP vertical slice: open key, sign CMS,
// verify chain, and build an OCSP request. See go/examples/demo/ for a runnable program.
func Example_workflow() {
	rootCert := readTestdata(nil, "pki", "pki_example", "root_certificate.cer")
	userKey := readTestdata(nil, "pki", "pki_example", "userfiz_private_key_ba.dat")
	userCert := readTestdata(nil, "pki", "pki_example", "userfiz_certificate.cer")

	key, err := uacryptex.OpenPrivateKey(userKey, userCert)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer key.Close()

	payload := []byte("Статус повідомлення")
	cms, err := uacryptex.SignCMS(payload, key)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if err := uacryptex.VerifyCMS(payload, cms); err != nil {
		fmt.Println("verify failed:", err)
		return
	}
	if err := uacryptex.VerifyCertificate(userCert, rootCert); err != nil {
		fmt.Println("chain failed:", err)
		return
	}
	if _, err := uacryptex.OcspRequestFromCert(rootCert, userCert); err != nil {
		fmt.Println("ocsp failed:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}
