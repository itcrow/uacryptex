import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'bindings.dart';
import 'library.dart';

/// Cached FFI bindings for `uacryptex.h`.
final NativeApi native = NativeApi._();

class NativeApi {
  NativeApi._();

  late final DynamicLibrary _lib = openUacryptexLibrary();

  late final ErrorInitDart errorInit =
      _lib.lookupFunction<ErrorInitNative, ErrorInitDart>('uacryptex_error_init');

  late final BufFreeDart bufFree =
      _lib.lookupFunction<BufFreeNative, BufFreeDart>('uacryptex_buf_free');

  late final HandleFreeDart handleFree =
      _lib.lookupFunction<HandleFreeNative, HandleFreeDart>('uacryptex_handle_free');

  late final VersionDart version =
      _lib.lookupFunction<VersionNative, VersionDart>('uacryptex_version');

  late final SignOpenDart signOpen =
      _lib.lookupFunction<SignOpenNative, SignOpenDart>('uacryptex_sign_open');

  late final Pkcs12OpenDart pkcs12Open =
      _lib.lookupFunction<Pkcs12OpenNative, Pkcs12OpenDart>('uacryptex_pkcs12_open');

  late final SignHashDart signHash =
      _lib.lookupFunction<SignHashNative, SignHashDart>('uacryptex_sign_hash');

  late final SignHashDart signData = _lib
      .lookupFunction<SignHashNative, SignHashDart>('uacryptex_sign_data');

  late final CmsSignDart cmsSign =
      _lib.lookupFunction<CmsSignNative, CmsSignDart>('uacryptex_cms_sign');

  late final CmsVerifyDart cmsVerify =
      _lib.lookupFunction<CmsVerifyNative, CmsVerifyDart>('uacryptex_cms_verify');

  late final ExtCreateSubjAltNameDart extCreateSubjAltName = _lib.lookupFunction<
      ExtCreateSubjAltNameNative, ExtCreateSubjAltNameDart>('uacryptex_ext_create_subj_alt_name');

  late final _ExtDnsEmailNative _extDnsEmail = _lib.lookupFunction<_ExtDnsEmailNative,
      _ExtDnsEmailDart>('uacryptex_ext_create_subj_alt_name_dns_email');

  late final _ExtKeyUsageNative _extKeyUsage = _lib.lookupFunction<_ExtKeyUsageNative,
      _ExtKeyUsageDart>('uacryptex_ext_create_key_usage');

  late final _ExtAnyNative _extAny =
      _lib.lookupFunction<_ExtAnyNative, _ExtAnyDart>('uacryptex_ext_create_any');

  late final _Pkcs8OpenNative _pkcs8Open =
      _lib.lookupFunction<_Pkcs8OpenNative, _Pkcs8OpenDart>('uacryptex_pkcs8_open');

  late final _DigestNative _digest =
      _lib.lookupFunction<_DigestNative, _DigestDart>('uacryptex_digest');

  late final _VerifyHashNative _verifyHash =
      _lib.lookupFunction<_VerifyHashNative, _VerifyHashDart>('uacryptex_verify_hash');

  late final _VerifyDataNative _verifyData =
      _lib.lookupFunction<_VerifyDataNative, _VerifyDataDart>('uacryptex_verify_data');

  late final _CertVerifyNative _certVerify =
      _lib.lookupFunction<_CertVerifyNative, _CertVerifyDart>('uacryptex_cert_verify');

  late final _CertValidityNative _certCheckValidity = _lib.lookupFunction<_CertValidityNative,
      _CertValidityDart>('uacryptex_cert_check_validity');

  late final _CertSpkiNative _certSpki =
      _lib.lookupFunction<_CertSpkiNative, _CertSpkiDart>('uacryptex_cert_spki');

  late final _CrlVerifyNative _crlVerify =
      _lib.lookupFunction<_CrlVerifyNative, _CrlVerifyDart>('uacryptex_crl_verify');

  late final _CrlCheckNative _crlCheckCert =
      _lib.lookupFunction<_CrlCheckNative, _CrlCheckDart>('uacryptex_crl_check_cert');

  late final _Pkcs12SetCertsNative _pkcs12SetCertificates = _lib.lookupFunction<
      _Pkcs12SetCertsNative, _Pkcs12SetCertsDart>('uacryptex_pkcs12_set_certificates');

  late final _Pkcs12CountNative _pkcs12CertificateCount = _lib.lookupFunction<_Pkcs12CountNative,
      _Pkcs12CountDart>('uacryptex_pkcs12_certificate_count');

  late final _Pkcs12GetCertNative _pkcs12GetCertificate = _lib.lookupFunction<_Pkcs12GetCertNative,
      _Pkcs12GetCertDart>('uacryptex_pkcs12_get_certificate');

  late final _OcspReqFromCertNative _ocspRequestFromCert = _lib.lookupFunction<
      _OcspReqFromCertNative, _OcspReqFromCertDart>('uacryptex_ocsp_request_from_cert');

  late final _OcspRespVerifyNative _ocspResponseVerify = _lib.lookupFunction<
      _OcspRespVerifyNative, _OcspRespVerifyDart>('uacryptex_ocsp_response_verify');

  late final _TspReqDataNative _tspRequestFromData =
      _lib.lookupFunction<_TspReqDataNative, _TspReqDataDart>('uacryptex_tsp_request_from_data');

  late final _TspRespVerifyNative _tspResponseVerify = _lib.lookupFunction<_TspRespVerifyNative,
      _TspRespVerifyDart>('uacryptex_tsp_response_verify');

  late final _CsrVerifyNative _csrVerify =
      _lib.lookupFunction<_CsrVerifyNative, _CsrVerifyDart>('uacryptex_csr_verify');

  late final _EnvelopEncryptNative _cmsEnvelopEncrypt = _lib.lookupFunction<_EnvelopEncryptNative,
      _EnvelopEncryptDart>('uacryptex_cms_envelop_encrypt');

  late final _EnvelopDecryptNative _cmsEnvelopDecrypt = _lib.lookupFunction<_EnvelopDecryptNative,
      _EnvelopDecryptDart>('uacryptex_cms_envelop_decrypt');

  late final _CmsSignCadesTNative _cmsSignCadesT =
      _lib.lookupFunction<_CmsSignCadesTNative, _CmsSignCadesTDart>('uacryptex_cms_sign_cades_t');

  late final _CmsSignCadesCNative _cmsSignCadesC =
      _lib.lookupFunction<_CmsSignCadesCNative, _CmsSignCadesCDart>('uacryptex_cms_sign_cades_c');

  late final _CmsSignCadesXNative _cmsSignCadesX =
      _lib.lookupFunction<_CmsSignCadesXNative, _CmsSignCadesXDart>('uacryptex_cms_sign_cades_x');

  late final _CmsSignCadesLtNative _cmsSignCadesLt = _lib.lookupFunction<_CmsSignCadesLtNative,
      _CmsSignCadesLtDart>('uacryptex_cms_sign_cades_lt');

  late final _CmsSignCadesANative _cmsSignCadesA =
      _lib.lookupFunction<_CmsSignCadesANative, _CmsSignCadesADart>('uacryptex_cms_sign_cades_a');

  late final _CsrGenerateNative _csrGenerate =
      _lib.lookupFunction<_CsrGenerateNative, _CsrGenerateDart>('uacryptex_csr_generate');

  late final _CertGenerateNative _certGenerate =
      _lib.lookupFunction<_CertGenerateNative, _CertGenerateDart>('uacryptex_cert_generate');

  late final _CrlGenerateNative _crlGenerate =
      _lib.lookupFunction<_CrlGenerateNative, _CrlGenerateDart>('uacryptex_crl_generate');

  int extCreateSubjAltNameDnsEmail(
    int critical,
    Pointer<Utf8> dns,
    Pointer<Utf8> email,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _extDnsEmail(critical, dns, email, out, err);

  int extCreateKeyUsage(
    int critical,
    int usageBits,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _extKeyUsage(critical, usageBits, out, err);

  int extCreateAny(
    int critical,
    Pointer<Utf8> oid,
    Pointer<Uint8> value,
    int valueLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _extAny(critical, oid, value, valueLen, out, err);

  int pkcs8Open(
    Pointer<Uint8> der,
    int derLen,
    Pointer<Pointer<UacryptexHandle>> out,
    Pointer<UacryptexError> err,
  ) =>
      _pkcs8Open(der, derLen, out, err);

  int digest(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<Uint8> algorithmAid,
    int algorithmAidLen,
    Pointer<Uint8> cert,
    int certLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _digest(data, dataLen, algorithmAid, algorithmAidLen, cert, certLen, out, err);

  int verifyHash(
    Pointer<Uint8> digest,
    int digestLen,
    Pointer<Uint8> signature,
    int signatureLen,
    Pointer<Uint8> cert,
    int certLen,
    Pointer<UacryptexError> err,
  ) =>
      _verifyHash(digest, digestLen, signature, signatureLen, cert, certLen, err);

  int verifyData(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<Uint8> signature,
    int signatureLen,
    Pointer<Uint8> cert,
    int certLen,
    Pointer<UacryptexError> err,
  ) =>
      _verifyData(data, dataLen, signature, signatureLen, cert, certLen, err);

  int certVerify(
    Pointer<Uint8> cert,
    int certLen,
    Pointer<Uint8> issuer,
    int issuerLen,
    Pointer<UacryptexError> err,
  ) =>
      _certVerify(cert, certLen, issuer, issuerLen, err);

  int certCheckValidity(Pointer<Uint8> cert, int certLen, int unixSecs, Pointer<UacryptexError> err) =>
      _certCheckValidity(cert, certLen, unixSecs, err);

  int certSpki(Pointer<Uint8> cert, int certLen, Pointer<UacryptexBuf> out, Pointer<UacryptexError> err) =>
      _certSpki(cert, certLen, out, err);

  int crlVerify(Pointer<Uint8> crl, int crlLen, Pointer<Uint8> issuer, int issuerLen, Pointer<UacryptexError> err) =>
      _crlVerify(crl, crlLen, issuer, issuerLen, err);

  int crlCheckCert(
    Pointer<Uint8> crl,
    int crlLen,
    Pointer<Uint8> cert,
    int certLen,
    Pointer<Int32> outRevoked,
    Pointer<UacryptexError> err,
  ) =>
      _crlCheckCert(crl, crlLen, cert, certLen, outRevoked, err);

  int pkcs12SetCertificates(Pointer<UacryptexHandle> store, Pointer<Uint8> cert, int certLen, Pointer<UacryptexError> err) =>
      _pkcs12SetCertificates(store, cert, certLen, err);

  int pkcs12CertificateCount(Pointer<UacryptexHandle> store, Pointer<IntPtr> out, Pointer<UacryptexError> err) =>
      _pkcs12CertificateCount(store, out, err);

  int pkcs12GetCertificate(Pointer<UacryptexHandle> store, int index, Pointer<UacryptexBuf> out, Pointer<UacryptexError> err) =>
      _pkcs12GetCertificate(store, index, out, err);

  int ocspRequestFromCert(
    Pointer<Uint8> root,
    int rootLen,
    Pointer<Uint8> user,
    int userLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _ocspRequestFromCert(root, rootLen, user, userLen, out, err);

  int ocspResponseVerify(Pointer<Uint8> response, int responseLen, Pointer<Uint8> issuer, int issuerLen, Pointer<UacryptexError> err) =>
      _ocspResponseVerify(response, responseLen, issuer, issuerLen, err);

  int tspRequestFromData(Pointer<Uint8> data, int dataLen, Pointer<Utf8> policyOid, int certReq, Pointer<UacryptexBuf> out, Pointer<UacryptexError> err) =>
      _tspRequestFromData(data, dataLen, policyOid, certReq, out, err);

  int tspResponseVerify(Pointer<Uint8> response, int responseLen, Pointer<Uint8> tsaCert, int tsaCertLen, Pointer<UacryptexError> err) =>
      _tspResponseVerify(response, responseLen, tsaCert, tsaCertLen, err);

  int csrVerify(Pointer<Uint8> csr, int csrLen, Pointer<UacryptexError> err) => _csrVerify(csr, csrLen, err);

  int cmsEnvelopEncrypt(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> recipientKey,
    Pointer<Uint8> recipientCert,
    int recipientCertLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsEnvelopEncrypt(data, dataLen, recipientKey, recipientCert, recipientCertLen, out, err);

  int cmsEnvelopDecrypt(
    Pointer<Uint8> cms,
    int cmsLen,
    Pointer<Uint8> external,
    int externalLen,
    Pointer<Uint8> originatorCert,
    int originatorCertLen,
    Pointer<UacryptexHandle> recipientKey,
    Pointer<Uint8> recipientCert,
    int recipientCertLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsEnvelopDecrypt(
        cms,
        cmsLen,
        external,
        externalLen,
        originatorCert,
        originatorCertLen,
        recipientKey,
        recipientCert,
        recipientCertLen,
        out,
        err,
      );

  int cmsSignCadesT(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> signKey,
    Pointer<UacryptexHandle> tsaKey,
    Pointer<Uint8> serial,
    int serialLen,
    int currentTime,
    Pointer<Utf8> policyOid,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsSignCadesT(data, dataLen, signKey, tsaKey, serial, serialLen, currentTime, policyOid, out, err);

  int cmsSignCadesC(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> signKey,
    Pointer<Uint8> refCert,
    int refCertLen,
    Pointer<Uint8> refCrl,
    int refCrlLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsSignCadesC(data, dataLen, signKey, refCert, refCertLen, refCrl, refCrlLen, out, err);

  int cmsSignCadesX(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> signKey,
    Pointer<Uint8> refCert,
    int refCertLen,
    Pointer<Uint8> ocspResponse,
    int ocspResponseLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsSignCadesX(data, dataLen, signKey, refCert, refCertLen, ocspResponse, ocspResponseLen, out, err);

  int cmsSignCadesLt(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> signKey,
    Pointer<Uint8> refCert,
    int refCertLen,
    Pointer<Uint8> refCrl,
    int refCrlLen,
    Pointer<Uint8> ocspResponse,
    int ocspResponseLen,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsSignCadesLt(
        data,
        dataLen,
        signKey,
        refCert,
        refCertLen,
        refCrl,
        refCrlLen,
        ocspResponse,
        ocspResponseLen,
        out,
        err,
      );

  int cmsSignCadesA(
    Pointer<Uint8> data,
    int dataLen,
    Pointer<UacryptexHandle> signKey,
    Pointer<UacryptexHandle> tsaKey,
    Pointer<Uint8> refCert,
    int refCertLen,
    Pointer<Uint8> refCrl,
    int refCrlLen,
    Pointer<Uint8> ocspResponse,
    int ocspResponseLen,
    Pointer<Uint8> serial,
    int serialLen,
    int currentTime,
    Pointer<Utf8> policyOid,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _cmsSignCadesA(
        data,
        dataLen,
        signKey,
        tsaKey,
        refCert,
        refCertLen,
        refCrl,
        refCrlLen,
        ocspResponse,
        ocspResponseLen,
        serial,
        serialLen,
        currentTime,
        policyOid,
        out,
        err,
      );

  int csrGenerate(
    Pointer<UacryptexHandle> key,
    Pointer<Utf8> subject,
    Pointer<Utf8> dns,
    Pointer<Utf8> email,
    Pointer<Utf8> subjectDirAttr,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _csrGenerate(key, subject, dns, email, subjectDirAttr, out, err);

  int certGenerate(
    Pointer<UacryptexHandle> caKey,
    Pointer<Uint8> csr,
    int csrLen,
    int version,
    Pointer<Uint8> serial,
    int serialLen,
    int notBefore,
    int notAfter,
    int selfSigned,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _certGenerate(caKey, csr, csrLen, version, serial, serialLen, notBefore, notAfter, selfSigned, out, err);

  int crlGenerate(
    Pointer<UacryptexHandle> caKey,
    Pointer<Uint8> previousCrl,
    int previousCrlLen,
    int crlType,
    int diffNextUpdateSecs,
    Pointer<Uint8> mergeDeltaCrl,
    int mergeDeltaCrlLen,
    Pointer<Uint8> revokeSerial,
    int revokeSerialLen,
    Pointer<Utf8> templateName,
    Pointer<Utf8> description,
    Pointer<UacryptexBuf> out,
    Pointer<UacryptexError> err,
  ) =>
      _crlGenerate(
        caKey,
        previousCrl,
        previousCrlLen,
        crlType,
        diffNextUpdateSecs,
        mergeDeltaCrl,
        mergeDeltaCrlLen,
        revokeSerial,
        revokeSerialLen,
        templateName,
        description,
        out,
        err,
      );
}

// Private typedefs for additional symbols (keeps bindings.dart smaller).

typedef _ExtDnsEmailNative = Int32 Function(
    Int32, Pointer<Utf8>, Pointer<Utf8>, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _ExtDnsEmailDart = int Function(
    int, Pointer<Utf8>, Pointer<Utf8>, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _ExtKeyUsageNative = Int32 Function(
    Int32, Uint32, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _ExtKeyUsageDart = int Function(
    int, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _ExtAnyNative = Int32 Function(Int32, Pointer<Utf8>, Pointer<Uint8>, IntPtr,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _ExtAnyDart = int Function(int, Pointer<Utf8>, Pointer<Uint8>, int,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _Pkcs8OpenNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Pointer<UacryptexHandle>>, Pointer<UacryptexError>);
typedef _Pkcs8OpenDart = int Function(
    Pointer<Uint8>, int, Pointer<Pointer<UacryptexHandle>>, Pointer<UacryptexError>);

typedef _DigestNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
    Pointer<Uint8>, IntPtr, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _DigestDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _VerifyHashNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
    Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _VerifyHashDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<UacryptexError>);

typedef _VerifyDataNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
    Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _VerifyDataDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<UacryptexError>);

typedef _CertVerifyNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _CertVerifyDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _CertValidityNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Int64, Pointer<UacryptexError>);
typedef _CertValidityDart = int Function(
    Pointer<Uint8>, int, int, Pointer<UacryptexError>);

typedef _CertSpkiNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _CertSpkiDart = int Function(
    Pointer<Uint8>, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _CrlVerifyNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _CrlVerifyDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _CrlCheckNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
    Pointer<Int32>, Pointer<UacryptexError>);
typedef _CrlCheckDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Int32>,
    Pointer<UacryptexError>);

typedef _Pkcs12SetCertsNative = Int32 Function(
    Pointer<UacryptexHandle>, Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _Pkcs12SetCertsDart = int Function(
    Pointer<UacryptexHandle>, Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _Pkcs12CountNative = Int32 Function(
    Pointer<UacryptexHandle>, Pointer<IntPtr>, Pointer<UacryptexError>);
typedef _Pkcs12CountDart = int Function(
    Pointer<UacryptexHandle>, Pointer<IntPtr>, Pointer<UacryptexError>);

typedef _Pkcs12GetCertNative = Int32 Function(Pointer<UacryptexHandle>, IntPtr,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _Pkcs12GetCertDart = int Function(
    Pointer<UacryptexHandle>, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _OcspReqFromCertNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _OcspReqFromCertDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _OcspRespVerifyNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _OcspRespVerifyDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _TspReqDataNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Utf8>, Int32,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _TspReqDataDart = int Function(Pointer<Uint8>, int, Pointer<Utf8>, int,
    Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _TspRespVerifyNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _TspRespVerifyDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _CsrVerifyNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<UacryptexError>);
typedef _CsrVerifyDart = int Function(Pointer<Uint8>, int, Pointer<UacryptexError>);

typedef _EnvelopEncryptNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<UacryptexHandle>,
    Pointer<Uint8>, IntPtr, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _EnvelopEncryptDart = int Function(Pointer<Uint8>, int, Pointer<UacryptexHandle>,
    Pointer<Uint8>, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _EnvelopDecryptNative = Int32 Function(
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
typedef _EnvelopDecryptDart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    int,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);

typedef _CmsSignCadesTNative = Int32 Function(
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexHandle>,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    IntPtr,
    Int64,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
typedef _CmsSignCadesTDart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<UacryptexHandle>,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    int,
    int,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);

typedef _CmsSignCadesCNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<UacryptexHandle>,
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _CmsSignCadesCDart = int Function(Pointer<Uint8>, int, Pointer<UacryptexHandle>,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _CmsSignCadesXNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<UacryptexHandle>,
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _CmsSignCadesXDart = int Function(Pointer<Uint8>, int, Pointer<UacryptexHandle>,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _CmsSignCadesLtNative = Int32 Function(
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
typedef _CmsSignCadesLtDart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);

typedef _CmsSignCadesANative = Int32 Function(
    Pointer<Uint8>,
    IntPtr,
    Pointer<UacryptexHandle>,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Int64,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
typedef _CmsSignCadesADart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<UacryptexHandle>,
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    int,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);

typedef _CsrGenerateNative = Int32 Function(Pointer<UacryptexHandle>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _CsrGenerateDart = int Function(Pointer<UacryptexHandle>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _CertGenerateNative = Int32 Function(Pointer<UacryptexHandle>, Pointer<Uint8>, IntPtr, Int32,
    Pointer<Uint8>, IntPtr, Int64, Int64, Int32, Pointer<UacryptexBuf>, Pointer<UacryptexError>);
typedef _CertGenerateDart = int Function(Pointer<UacryptexHandle>, Pointer<Uint8>, int, int,
    Pointer<Uint8>, int, int, int, int, Pointer<UacryptexBuf>, Pointer<UacryptexError>);

typedef _CrlGenerateNative = Int32 Function(
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    IntPtr,
    Int32,
    Int64,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Uint8>,
    IntPtr,
    Pointer<Utf8>,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
typedef _CrlGenerateDart = int Function(
    Pointer<UacryptexHandle>,
    Pointer<Uint8>,
    int,
    int,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Utf8>,
    Pointer<Utf8>,
    Pointer<UacryptexBuf>,
    Pointer<UacryptexError>);
