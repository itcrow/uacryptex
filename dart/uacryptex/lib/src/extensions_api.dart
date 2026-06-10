import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native/bindings.dart';
import 'native/ffi_util.dart';
import 'native/native_api.dart';

/// X.509 extension builders (DER-encoded `Extension` structures).
abstract final class X509Extensions {
  /// Build SubjectAltName from [kinds] / [names] pairs (see Rust `ext_create_subj_alt_name_directly`).
  static Uint8List createSubjectAltName({
    bool critical = false,
    required List<int> kinds,
    required List<String> names,
  }) {
    if (kinds.length != names.length || kinds.isEmpty) {
      throw ArgumentError('kinds and names must be the same non-empty length');
    }
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    final types = calloc<Int32>(kinds.length);
    final namePtrs = calloc<Pointer<Utf8>>(names.length);
    try {
      for (var i = 0; i < kinds.length; i++) {
        types[i] = kinds[i];
        namePtrs[i] = scope.utf8(names[i]);
      }
      final code = native.extCreateSubjAltName(
        critical ? 1 : 0,
        types,
        namePtrs,
        kinds.length,
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(types);
      calloc.free(namePtrs);
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }

  /// DNS + RFC822 SubjectAltName.
  static Uint8List createSubjectAltNameDnsEmail({
    bool critical = false,
    required String dns,
    required String email,
  }) {
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.extCreateSubjAltNameDnsEmail(
        critical ? 1 : 0,
        scope.utf8(dns),
        scope.utf8(email),
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }

  /// keyUsage extension; [usageBits] uses [KeyUsageBits] flags.
  static Uint8List createKeyUsage({
    bool critical = false,
    required int usageBits,
  }) {
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final code = native.extCreateKeyUsage(critical ? 1 : 0, usageBits, out, err);
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      calloc.free(out);
    }
  }

  /// Arbitrary extension from dotted [oid] and raw extnValue [value].
  static Uint8List createAny({
    bool critical = false,
    required String oid,
    required Uint8List value,
  }) {
    if (value.isEmpty) {
      throw ArgumentError('extension value must not be empty');
    }
    final scope = NativeCallScope();
    final err = allocError();
    final out = calloc<UacryptexBuf>();
    try {
      final valuePtr = scope.bytes(value);
      final code = native.extCreateAny(
        critical ? 1 : 0,
        scope.utf8(oid),
        valuePtr,
        value.length,
        out,
        err,
      );
      checkCode(code, err);
      return bufToBytes(out);
    } finally {
      calloc.free(err);
      calloc.free(out);
      scope.dispose();
    }
  }
}
