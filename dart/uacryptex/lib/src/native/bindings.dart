import 'dart:ffi';

import 'package:ffi/ffi.dart';

final class UacryptexBuf extends Struct {
  external Pointer<Uint8> ptr;

  @UintPtr()
  external int len;
}

final class UacryptexError extends Struct {
  @Int32()
  external int code;

  @Array(256)
  external Array<Uint8> message;
}

typedef UacryptexHandle = Pointer<Void>;

typedef ErrorInitNative = Void Function(Pointer<UacryptexError> err);
typedef ErrorInitDart = void Function(Pointer<UacryptexError> err);

typedef BufFreeNative = Void Function(UacryptexBuf buf);
typedef BufFreeDart = void Function(UacryptexBuf buf);

typedef HandleFreeNative = Void Function(Pointer<UacryptexHandle> handle);
typedef HandleFreeDart = void Function(Pointer<UacryptexHandle> handle);

typedef VersionNative = Int32 Function(Pointer<Utf8> out, IntPtr cap);
typedef VersionDart = int Function(Pointer<Utf8> out, int cap);

typedef SignOpenNative = Int32 Function(
  Pointer<Uint8> key,
  IntPtr keyLen,
  Pointer<Uint8> cert,
  IntPtr certLen,
  Pointer<Pointer<UacryptexHandle>> out,
  Pointer<UacryptexError> err,
);
typedef SignOpenDart = int Function(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> cert,
  int certLen,
  Pointer<Pointer<UacryptexHandle>> out,
  Pointer<UacryptexError> err,
);

typedef Pkcs12OpenNative = Int32 Function(
  Pointer<Uint8> data,
  IntPtr dataLen,
  Pointer<Utf8> password,
  Pointer<Pointer<UacryptexHandle>> out,
  Pointer<UacryptexError> err,
);
typedef Pkcs12OpenDart = int Function(
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Utf8> password,
  Pointer<Pointer<UacryptexHandle>> out,
  Pointer<UacryptexError> err,
);

typedef SignHashNative = Int32 Function(
  Pointer<Uint8> hash,
  IntPtr hashLen,
  Pointer<UacryptexHandle> key,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);
typedef SignHashDart = int Function(
  Pointer<Uint8> hash,
  int hashLen,
  Pointer<UacryptexHandle> key,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);

typedef CmsSignNative = Int32 Function(
  Pointer<Uint8> data,
  IntPtr dataLen,
  Pointer<UacryptexHandle> key,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);
typedef CmsSignDart = int Function(
  Pointer<Uint8> data,
  int dataLen,
  Pointer<UacryptexHandle> key,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);

typedef CmsVerifyNative = Int32 Function(
  Pointer<Uint8> data,
  IntPtr dataLen,
  Pointer<Uint8> cms,
  IntPtr cmsLen,
  Pointer<UacryptexError> err,
);
typedef CmsVerifyDart = int Function(
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Uint8> cms,
  int cmsLen,
  Pointer<UacryptexError> err,
);

typedef ExtCreateSubjAltNameNative = Int32 Function(
  Int32 critical,
  Pointer<Int32> types,
  Pointer<Pointer<Utf8>> names,
  IntPtr count,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);
typedef ExtCreateSubjAltNameDart = int Function(
  int critical,
  Pointer<Int32> types,
  Pointer<Pointer<Utf8>> names,
  int count,
  Pointer<UacryptexBuf> out,
  Pointer<UacryptexError> err,
);

String errorMessage(Pointer<UacryptexError> err) {
  final bytes = err.ref.message;
  final end = bytes.indexOf(0);
  final len = end < 0 ? 256 : end;
  return String.fromCharCodes(List.generate(len, (i) => bytes[i]));
}
