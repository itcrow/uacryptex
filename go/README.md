# uacryptex Go module

Go bindings for Ukrainian cryptography (DSTU/GOST PKI) via `uacryptex-ffi`.

**Full client guide (all languages):** [docs/CLIENT_LIBRARIES.md](../docs/CLIENT_LIBRARIES.md)

## Prerequisites

- Go 1.22+
- **CGO enabled** (`CGO_ENABLED=1`)
- Prebuilt native library for your platform:

```bash
# from repository root
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh
```

Or download a release artifact: `./scripts/fetch-native-lib.sh`

## Install

```bash
go get github.com/itcrow/uacryptex/uacryptex@v0.1.0
```

The module links against static `libuacryptex_ffi.a` under `go/native/lib/{GOOS}/{GOARCH}/`.

## Examples

| Example | Command |
|---------|---------|
| Full PKI walkthrough | `CGO_ENABLED=1 go run ./examples/demo/` |
| **Sign a document (.p7s)** | `CGO_ENABLED=1 go run ./examples/sign-document/` |

### Sign a document

Produces a CMS SignedData file (CAdES-BES) from any file on disk:

```bash
cd go
CGO_ENABLED=1 go run ./examples/sign-document/ \
  -doc /path/to/document.pdf \
  -key /path/to/private_key.dat \
  -cert /path/to/certificate.cer \
  -out /path/to/document.p7s
```

PKCS#12 keystore:

```bash
CGO_ENABLED=1 go run ./examples/sign-document/ \
  -doc contract.xml -p12 user.pfx -password secret -out contract.xml.p7s
```

Verify later (same document bytes + CMS):

```go
document, _ := os.ReadFile("document.pdf")
cms, _ := os.ReadFile("document.p7s")
if err := uacryptex.VerifyCMS(document, cms); err != nil {
    log.Fatal(err)
}
```

Demo mode (no flags) uses `testdata/documents/sample.txt` and writes CMS to `$TMPDIR/sample.txt.p7s`.

## Demo

Runnable walkthrough (CMS, CAdES-T/C, enveloped data, OCSP, PKCS#12):

```bash
cd go
CGO_ENABLED=1 go run ./examples/demo/
```

Uses `testdata/pki/pki_example/` from the monorepo checkout.

## Tests

```bash
cd go
CGO_ENABLED=1 go test ./...
```

## Minimal example

```go
package main

import (
	"fmt"
	"os"

	"github.com/itcrow/uacryptex/uacryptex"
)

func main() {
	key, err := uacryptex.OpenPrivateKey(keyDER, certDER)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer key.Close()

	payload := []byte("document body")
	cms, err := uacryptex.SignCMS(payload, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := uacryptex.VerifyCMS(payload, cms); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("CMS ok")
}
```

Godoc examples: `go doc -all github.com/itcrow/uacryptex/uacryptex` (see `example_test.go`).
