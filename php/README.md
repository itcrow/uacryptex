# uacryptex PHP bindings

PHP 8.1+ bindings using the **FFI** extension over `uacryptex-ffi`.

**Full guide (all languages):** [docs/CLIENT_LIBRARIES.md](../docs/CLIENT_LIBRARIES.md)

## Prerequisites

```bash
# From repository root
./scripts/build-ffi.sh
```

Enable FFI in `php.ini` (`ffi.enable=true` for CLI tests).

Set `UACRYPTEX_LIB` if the shared library is not under `native/lib/{platform}/{arch}/`.

## Install

```bash
cd php
composer install
```

## Usage

```php
<?php
use Itcrow\Uacryptex\Uacryptex;

echo Uacryptex::libraryVersion();

$ks = Uacryptex::openPkcs12($p12Bytes, 'password');
try {
    $key = $ks->privateKey();
    $cms = Uacryptex::signCms($payload, $key);
    Uacryptex::verifyCms($payload, $cms);
} finally {
    $ks->close();
}
```

## Tests

```bash
cd php && php -d ffi.enable=1 tests/VersionTest.php
```

Composer autoload is optional (`composer install` in `php/` for local dev). For Packagist use root `composer.json` (`itcrow/uacryptex`).
