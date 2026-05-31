# uacryptex Node.js bindings

Node.js 18+ bindings via [koffi](https://github.com/Koromix/koffi) over `uacryptex-ffi`.

**Full guide (all languages):** [docs/CLIENT_LIBRARIES.md](../docs/CLIENT_LIBRARIES.md)

## Prerequisites

```bash
# From repository root
./scripts/build-ffi.sh
```

Set `UACRYPTEX_LIB` to the shared library path if not using the default under `native/lib/`.

## Install

```bash
cd nodejs
npm install
```

## Usage

```javascript
const uacryptex = require('@itcrow/uacryptex');

console.log(uacryptex.libraryVersion());

const ks = uacryptex.openPkcs12(p12Buffer, 'password');
try {
  const key = ks.privateKey();
  const cms = uacryptex.signCms(Buffer.from('payload'), key);
  uacryptex.verifyCms(Buffer.from('payload'), cms);
} finally {
  ks.close();
}
```

## Tests

```bash
cd nodejs && npm test
```
