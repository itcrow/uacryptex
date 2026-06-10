import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native/bindings.dart';
import 'native/ffi_util.dart';
import 'native/native_api.dart';

/// Signing key backed by uacryptex-core (DSTU4145, ECDSA, …).
class PrivateKey {
  PrivateKey._(this._handle);

  final Pointer<UacryptexHandle> _handle;
  var _closed = false;

  Pointer<UacryptexHandle> get handle {
    if (_closed) throw StateError('closed private key');
    return _handle;
  }

  void close() {
    if (!_closed) {
      native.handleFree(_handle);
      _closed = true;
    }
  }

  Uint8List signHash(Uint8List digest) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final digestPtr = scope.bytes(digest);
      final code = native.signHash(digestPtr, digest.length, _handle, out, err);
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  Uint8List signData(Uint8List data) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final dataPtr = scope.bytes(data);
      final code = native.signData(dataPtr, data.length, _handle, out, err);
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  Uint8List csrGenerate({
    required String subject,
    String? dns,
    String? email,
    String? subjectDirAttr,
  }) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.csrGenerate(
        _handle,
        scope.utf8(subject),
        scope.utf8(dns),
        scope.utf8(email),
        scope.utf8(subjectDirAttr),
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  Uint8List generateCertificate({
    required Uint8List csr,
    required int version,
    required Uint8List serial,
    required int notBeforeUnix,
    required int notAfterUnix,
    bool selfSigned = false,
  }) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.certGenerate(
        _handle,
        scope.bytes(csr),
        csr.length,
        version,
        scope.bytes(serial),
        serial.length,
        notBeforeUnix,
        notAfterUnix,
        selfSigned ? 1 : 0,
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  Uint8List generateCrl({
    Uint8List? previousCrl,
    required int crlType,
    required int diffNextUpdateSecs,
    Uint8List? mergeDeltaCrl,
    Uint8List? revokeSerial,
    String templateName = '',
    String description = '',
  }) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.crlGenerate(
        _handle,
        scope.bytes(previousCrl),
        previousCrl?.length ?? 0,
        crlType,
        diffNextUpdateSecs,
        scope.bytes(mergeDeltaCrl),
        mergeDeltaCrl?.length ?? 0,
        scope.bytes(revokeSerial),
        revokeSerial?.length ?? 0,
        scope.utf8(templateName),
        scope.utf8(description),
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      scope.dispose();
    }
  }

  static PrivateKey open({required Uint8List keyDer, required Uint8List certDer}) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<Pointer<UacryptexHandle>>();
    try {
      final code = native.signOpen(
        scope.bytes(keyDer),
        keyDer.length,
        scope.bytes(certDer),
        certDer.length,
        out,
        err,
      );
      checkCode(code, err);
      return PrivateKey._(out.value);
    } finally {
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }

  static PrivateKey openPkcs8(Uint8List der) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<Pointer<UacryptexHandle>>();
    try {
      final code = native.pkcs8Open(scope.bytes(der), der.length, out, err);
      checkCode(code, err);
      return PrivateKey._(out.value);
    } finally {
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }
}
