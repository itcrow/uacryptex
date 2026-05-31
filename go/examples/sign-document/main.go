// Sign a document file and produce a CMS SignedData container (CAdES-BES subset).
//
// The signature is detached at the API level: uacryptex signs the document bytes
// and returns a CMS blob (.p7s). Verification needs both the original document
// and the CMS file.
//
// Prerequisites: CGO_ENABLED=1, native lib built (see go/README.md).
//
// Demo mode (repository test fixtures):
//
//	cd go && CGO_ENABLED=1 go run ./examples/sign-document/
//
// Production use:
//
//	go run ./examples/sign-document/ \
//	  -doc /path/to/document.pdf \
//	  -key /path/to/private_key.dat \
//	  -cert /path/to/certificate.cer \
//	  -out /path/to/document.p7s
//
// PKCS#12 keystore:
//
//	go run ./examples/sign-document/ \
//	  -doc contract.xml -p12 user.pfx -password secret -out contract.xml.p7s
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/itcrow/uacryptex/uacryptex"
)

func main() {
	docPath := flag.String("doc", "", "document file to sign")
	keyPath := flag.String("key", "", "signer private key (raw bytes)")
	certPath := flag.String("cert", "", "signer certificate (DER)")
	p12Path := flag.String("p12", "", "PKCS#12 keystore instead of -key/-cert")
	password := flag.String("password", "", "PKCS#12 password")
	outPath := flag.String("out", "", "output CMS file (.p7s)")
	flag.Parse()

	if *docPath == "" {
		if err := runDemo(); err != nil {
			fmt.Fprintf(os.Stderr, "demo: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: -out is required")
		os.Exit(2)
	}

	doc, err := os.ReadFile(*docPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read document: %v\n", err)
		os.Exit(1)
	}

	key, cleanup, err := openSigner(*keyPath, *certPath, *p12Path, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open signer: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	if err := signDocument(doc, key, *outPath); err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("signed %s → %s (%d bytes document, CMS written)\n", *docPath, *outPath, len(doc))
}

func runDemo() error {
	doc, err := readTestdata("documents", "sample.txt")
	if err != nil {
		return err
	}
	keyBytes, err := readTestdata("pki", "pki_example", "userfiz_private_key_ba.dat")
	if err != nil {
		return err
	}
	cert, err := readTestdata("pki", "pki_example", "userfiz_certificate.cer")
	if err != nil {
		return err
	}

	key, err := uacryptex.OpenPrivateKey(keyBytes, cert)
	if err != nil {
		return fmt.Errorf("OpenPrivateKey: %w", err)
	}
	defer key.Close()

	out := filepath.Join(os.TempDir(), "sample.txt.p7s")
	if err := signDocument(doc, key, out); err != nil {
		return err
	}

	cms, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	fmt.Printf("demo: signed testdata/documents/sample.txt\n")
	fmt.Printf("  document : %d bytes\n", len(doc))
	fmt.Printf("  CMS      : %s (%d bytes)\n", out, len(cms))
	fmt.Println("  verify   : ok")
	return nil
}

func signDocument(document []byte, key *uacryptex.PrivateKey, outPath string) error {
	cms, err := uacryptex.SignCMS(document, key)
	if err != nil {
		return fmt.Errorf("SignCMS: %w", err)
	}
	if err := uacryptex.VerifyCMS(document, cms); err != nil {
		return fmt.Errorf("VerifyCMS: %w", err)
	}
	if err := os.WriteFile(outPath, cms, 0o644); err != nil {
		return fmt.Errorf("write CMS: %w", err)
	}
	return nil
}

func openSigner(keyPath, certPath, p12Path, password string) (*uacryptex.PrivateKey, func(), error) {
	if p12Path != "" {
		p12, err := os.ReadFile(p12Path)
		if err != nil {
			return nil, nil, err
		}
		ks, err := uacryptex.OpenPKCS12(p12, password)
		if err != nil {
			return nil, nil, err
		}
		key := ks.PrivateKey()
		if key == nil {
			ks.Close()
			return nil, nil, fmt.Errorf("PKCS#12 has no private key")
		}
		return key, ks.Close, nil
	}
	if keyPath == "" || certPath == "" {
		return nil, nil, fmt.Errorf("provide -key and -cert, or -p12")
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := uacryptex.OpenPrivateKey(keyBytes, cert)
	if err != nil {
		return nil, nil, err
	}
	return key, key.Close, nil
}
