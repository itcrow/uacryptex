import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native/bindings.dart';
import 'native/ffi_util.dart';
import 'native/native_api.dart';
import 'private_key.dart';

/// Opened PKCS#12 container.
class Keystore {
  Keystore._(this._handle);

  final Pointer<UacryptexHandle> _handle;
  var _closed = false;

  void close() {
    if (!_closed) {
      native.handleFree(_handle);
      _closed = true;
    }
  }

  PrivateKey privateKey() => PrivateKey._(_handle);

  void setCertificate(Uint8List certDer) {
    final scope = NativeCallScope();
    final err = allocError();
    try {
      final code = native.pkcs12SetCertificates(_handle, scope.bytes(certDer), certDer.length, err);
      checkCode(code, err);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  int certificateCount() {
    final err = allocError();
    final out = calloc<IntPtr>();
    try {
      final code = native.pkcs12CertificateCount(_handle, out, err);
      checkCode(code, err);
      return out.value;
    } finally {
      calloc.free(err);
      calloc.free(out);
    }
  }

  Uint8List certificateAt(int index) {
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.pkcs12GetCertificate(_handle, index, out, err);
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      calloc.free(out);
    }
  }

  static Keystore open(Uint8List data, String password) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<Pointer<UacryptexHandle>>();
    try {
      final code = native.pkcs12Open(scope.bytes(data), data.length, scope.utf8(password), out, err);
      checkCode(code, err);
      return Keystore._(out.value);
    } finally {
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }
}
