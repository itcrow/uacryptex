import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errors.dart';
import 'keystore.dart';
import 'native/bindings.dart';
import 'native/ffi_util.dart';
import 'native/native_api.dart';
import 'private_key.dart';

const String packageVersion = '0.1.0';

String libraryVersion() {
  final buf = calloc<Uint8>(64);
  try {
    final code = native.version(buf.cast<Utf8>(), 64);
    if (code != RetCode.ok) {
      throw UacryptexException('uacryptex_version failed with code $code');
    }
    return buf.cast<Utf8>().toDartString();
  } finally {
    calloc.free(buf);
  }
}

PrivateKey openPrivateKey({required Uint8List keyDer, required Uint8List certDer}) =>
    PrivateKey.open(keyDer: keyDer, certDer: certDer);

Keystore openPkcs12(Uint8List data, String password) => Keystore.open(data, password);

PrivateKey openPkcs8(Uint8List der) => PrivateKey.openPkcs8(der);

Uint8List signCms(Uint8List data, PrivateKey key) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.cmsSign(scope.bytes(data), data.length, key.handle, out, err);
    checkCode(code, err);
    return bufToBytes(out);
  } finally {
    calloc.free(err);
    calloc.free(out);
    scope.dispose();
  }
}

void verifyCms(Uint8List data, Uint8List cms) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.cmsVerify(scope.bytes(data), data.length, scope.bytes(cms), cms.length, err);
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

Uint8List digest(
  Uint8List data, {
  Uint8List? algorithmAid,
  Uint8List? cert,
}) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.digest(
      scope.bytes(data),
      data.length,
      scope.bytes(algorithmAid),
      algorithmAid?.length ?? 0,
      scope.bytes(cert),
      cert?.length ?? 0,
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

void verifyHash(Uint8List digestBytes, Uint8List signature, Uint8List cert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.verifyHash(
      scope.bytes(digestBytes),
      digestBytes.length,
      scope.bytes(signature),
      signature.length,
      scope.bytes(cert),
      cert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

void verifyData(Uint8List data, Uint8List signature, Uint8List cert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.verifyData(
      scope.bytes(data),
      data.length,
      scope.bytes(signature),
      signature.length,
      scope.bytes(cert),
      cert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

void verifyCertificate(Uint8List cert, Uint8List issuerCert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.certVerify(
      scope.bytes(cert),
      cert.length,
      scope.bytes(issuerCert),
      issuerCert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

void checkCertificateValidity(Uint8List cert, int unixSecs) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.certCheckValidity(scope.bytes(cert), cert.length, unixSecs, err);
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

Uint8List certificateSpki(Uint8List cert) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.certSpki(scope.bytes(cert), cert.length, out, err);
    checkCode(code, err);
    return bufToBytes(out);
  } finally {
    calloc.free(err);
    calloc.free(out);
    scope.dispose();
  }
}

void verifyCrl(Uint8List crl, Uint8List issuerCert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.crlVerify(
      scope.bytes(crl),
      crl.length,
      scope.bytes(issuerCert),
      issuerCert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

bool isCertificateRevoked(Uint8List crl, Uint8List cert) {
  final scope = NativeCallScope();
  final err = allocError();
  final revoked = calloc<Int32>();
  try {
    final code = native.crlCheckCert(
      scope.bytes(crl),
      crl.length,
      scope.bytes(cert),
      cert.length,
      revoked,
      err,
    );
    checkCode(code, err);
    return revoked.value != 0;
  } finally {
    calloc.free(err);
    calloc.free(revoked);
    scope.dispose();
  }
}

Uint8List ocspRequestFromCert(Uint8List rootCert, Uint8List userCert) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.ocspRequestFromCert(
      scope.bytes(rootCert),
      rootCert.length,
      scope.bytes(userCert),
      userCert.length,
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

void ocspResponseVerify(Uint8List response, Uint8List issuerCert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.ocspResponseVerify(
      scope.bytes(response),
      response.length,
      scope.bytes(issuerCert),
      issuerCert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

Uint8List tspRequestFromData(Uint8List data, {String? policyOid, bool certReq = true}) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.tspRequestFromData(
      scope.bytes(data),
      data.length,
      scope.utf8(policyOid),
      certReq ? 1 : 0,
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

void tspResponseVerify(Uint8List response, Uint8List tsaCert) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.tspResponseVerify(
      scope.bytes(response),
      response.length,
      scope.bytes(tsaCert),
      tsaCert.length,
      err,
    );
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

void csrVerify(Uint8List csr) {
  final scope = NativeCallScope();
  final err = allocError();
  try {
    final code = native.csrVerify(scope.bytes(csr), csr.length, err);
    checkCode(code, err);
  } finally {
    calloc.free(err);
    scope.dispose();
  }
}

Uint8List envelopCms(Uint8List data, PrivateKey recipientKey, Uint8List recipientCert) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.cmsEnvelopEncrypt(
      scope.bytes(data),
      data.length,
      recipientKey.handle,
      scope.bytes(recipientCert),
      recipientCert.length,
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

Uint8List decryptCms(
  Uint8List cms, {
  Uint8List? external,
  Uint8List? originatorCert,
  required PrivateKey recipientKey,
  required Uint8List recipientCert,
}) {
  final scope = NativeCallScope();
  final err = allocError();
  final out = calloc<UacryptexBuf>();
  try {
    final code = native.cmsEnvelopDecrypt(
      scope.bytes(cms),
      cms.length,
      scope.bytes(external),
      external?.length ?? 0,
      scope.bytes(originatorCert),
      originatorCert?.length ?? 0,
      recipientKey.handle,
      scope.bytes(recipientCert),
      recipientCert.length,
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
