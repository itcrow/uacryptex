# uacryptex Dart / Flutter

Dart and Flutter bindings over the stable C ABI (`uacryptex-ffi`).

**Full guide (all languages):** [docs/CLIENT_LIBRARIES.md](../../docs/CLIENT_LIBRARIES.md)

## Prerequisites

From the repository root:

```bash
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh
```

Override library path: `UACRYPTEX_LIB=/path/to/libuacryptex_ffi.so`

## Use as a Dart package

```yaml
dependencies:
  uacryptex:
    path: ../dart/uacryptex   # monorepo path
```

```dart
import 'package:uacryptex/uacryptex.dart';

void main() {
  print(libraryVersion());
  final ks = openPkcs12(p12Bytes, 'password');
  try {
    final key = ks.privateKey();
    final cms = signCms(payload, key);
    verifyCms(payload, cms);
  } finally {
    ks.close();
  }
}
```

### X.509 extensions (FFI)

```dart
import 'package:uacryptex/uacryptex.dart';

final san = X509Extensions.createSubjectAltNameDnsEmail(
  dns: 'ca.ua',
  email: 'info@ca.ua',
);

final ku = X509Extensions.createKeyUsage(
  critical: true,
  usageBits: KeyUsageBits.keyCertSign | KeyUsageBits.crlSign,
);
```

DSTU `otherName` entries: use `X509Extensions.createSubjectAltName` with `GeneralNameKind.otherName` and values like `1.3.6.1.4.1.19398.1.1.4.2=utf8:…`.

## Use in Flutter

Add to `pubspec.yaml`:

```yaml
dependencies:
  uacryptex:
    path: ../../dart/uacryptex
```

The package registers a Flutter plugin so native libraries under `native/lib/` are bundled:

| Platform | Library loading |
|----------|-----------------|
| Linux / macOS / Windows | `native/lib/{os}/{arch}/shared/` |
| Android | `libuacryptex_ffi.so` in `android/src/main/jniLibs/` (synced by `sync-native-libs.sh`) |
| iOS | `DynamicLibrary.process()` when linked into the app |

**Android / iOS:** build or copy target `.so` / `.dylib` for the device ABI into the plugin `jniLibs` / iOS framework (see [docs/BINDINGS.md](../../docs/BINDINGS.md)). Desktop targets work after `build-ffi.sh` on the host.

## Tests

```bash
cd dart/uacryptex
dart pub get
dart test
```

Tests skip gracefully when the native library is missing.

## API parity

Matches Python / Node.js for CMS, PKCS#12, OCSP, TSP, CSR, CRL, enveloped CMS, plus **X.509 extension builders** (`X509Extensions`).
