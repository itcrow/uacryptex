import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../errors.dart';
import 'bindings.dart';
import 'native_api.dart';

Pointer<UacryptexError> allocError() {
  final err = calloc<UacryptexError>();
  native.errorInit(err);
  return err;
}

void checkCode(int code, Pointer<UacryptexError> err) {
  checkNative(code, errorMessage(err));
}

Uint8List bufToBytes(Pointer<UacryptexBuf> out) {
  final buf = out.ref;
  if (buf.ptr == nullptr || buf.len == 0) {
    native.bufFree(buf);
    return Uint8List(0);
  }
  final list = Uint8List.fromList(buf.ptr.asTypedList(buf.len));
  native.bufFree(buf);
  return list;
}

Pointer<Uint8> bytesToNative(Uint8List data) {
  final ptr = calloc<Uint8>(data.length);
  ptr.asTypedList(data.length).setAll(0, data);
  return ptr;
}

/// Holds native allocations for one FFI call; free with [dispose].
class NativeCallScope {
  final _ptrs = <Pointer>[];

  Pointer<Uint8> bytes(Uint8List? data) {
    if (data == null || data.isEmpty) return nullptr;
    final p = bytesToNative(data);
    _ptrs.add(p);
    return p;
  }

  Pointer<Utf8> utf8(String? text) {
    if (text == null) return nullptr;
    final p = text.toNativeUtf8();
    _ptrs.add(p);
    return p;
  }

  void dispose() {
    for (final p in _ptrs) {
      calloc.free(p);
    }
    _ptrs.clear();
  }
}
