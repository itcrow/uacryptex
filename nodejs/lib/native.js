'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const koffi = require('koffi');
const { RET_OK, mapNativeError } = require('./errors');

const UacryptexBuf = koffi.struct('UacryptexBuf', {
  ptr: 'void *',
  len: 'size_t',
});

const UacryptexError = koffi.struct('UacryptexError', {
  code: 'int32_t',
  message: koffi.array('char', 256),
});

let lib = null;
let fn = null;

function platformDir() {
  const system = os.platform();
  const arch = os.arch() === 'arm64' ? 'arm64' : 'amd64';
  const osName = system === 'win32' ? 'windows' : system === 'darwin' ? 'darwin' : 'linux';
  return { osName, arch };
}

function libFilename(osName) {
  if (osName === 'windows') return 'uacryptex_ffi.dll';
  if (osName === 'darwin') return 'libuacryptex_ffi.dylib';
  return 'libuacryptex_ffi.so';
}

function libCandidates() {
  const { osName, arch } = platformDir();
  const name = libFilename(osName);
  const rel = path.join('native', 'lib', osName, arch, 'shared', name);
  return [
    path.join(__dirname, '..', rel),
    path.join(__dirname, '..', '..', 'native', 'lib', osName, arch, 'shared', name),
  ];
}

function resolveLibPath(explicit) {
  if (explicit) return explicit;
  if (process.env.UACRYPTEX_LIB) return process.env.UACRYPTEX_LIB;
  for (const candidate of libCandidates()) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return libCandidates()[0];
}

function defaultLibPath() {
  return resolveLibPath(null);
}

function loadLibrary(libPath) {
  const resolved = resolveLibPath(libPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(
      `uacryptex native library not found: ${resolved}. ` +
        `Tried: ${libCandidates().join(', ')}. ` +
        'Run ./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh or set UACRYPTEX_LIB.'
    );
  }

  const handle = koffi.load(resolved);
  const UacryptexHandle = koffi.opaque('UacryptexHandle');

  return {
    handle,
    UacryptexHandle,
    uacryptex_error_init: handle.func('void uacryptex_error_init(UacryptexError *err)'),
    uacryptex_buf_free: handle.func('void uacryptex_buf_free(UacryptexBuf buf)'),
    uacryptex_handle_free: handle.func('void uacryptex_handle_free(UacryptexHandle *handle)'),
    uacryptex_version: handle.func('int32 uacryptex_version(_Out_ char *out, size_t cap)'),
    uacryptex_sign_open: handle.func(
      'int32 uacryptex_sign_open(const uint8_t *key, size_t key_len, const uint8_t *cert, size_t cert_len, _Out_ UacryptexHandle **out, UacryptexError *err)'
    ),
    uacryptex_pkcs12_open: handle.func(
      'int32 uacryptex_pkcs12_open(const uint8_t *data, size_t data_len, const char *password, _Out_ UacryptexHandle **out, UacryptexError *err)'
    ),
    uacryptex_pkcs12_set_certificates: handle.func(
      'int32 uacryptex_pkcs12_set_certificates(UacryptexHandle *store, const uint8_t *cert, size_t cert_len, UacryptexError *err)'
    ),
    uacryptex_sign_hash: handle.func(
      'int32 uacryptex_sign_hash(const uint8_t *hash, size_t hash_len, UacryptexHandle *key, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign: handle.func(
      'int32 uacryptex_cms_sign(const uint8_t *data, size_t data_len, UacryptexHandle *key, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign_cades_t: handle.func(
      'int32 uacryptex_cms_sign_cades_t(const uint8_t *data, size_t data_len, UacryptexHandle *sign_key, UacryptexHandle *tsa_key, const uint8_t *serial, size_t serial_len, int64 current_time, const char *policy_oid, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign_cades_c: handle.func(
      'int32 uacryptex_cms_sign_cades_c(const uint8_t *data, size_t data_len, UacryptexHandle *sign_key, const uint8_t *ref_cert, size_t ref_cert_len, const uint8_t *ref_crl, size_t ref_crl_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign_cades_x: handle.func(
      'int32 uacryptex_cms_sign_cades_x(const uint8_t *data, size_t data_len, UacryptexHandle *sign_key, const uint8_t *ref_cert, size_t ref_cert_len, const uint8_t *ocsp_response, size_t ocsp_response_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign_cades_lt: handle.func(
      'int32 uacryptex_cms_sign_cades_lt(const uint8_t *data, size_t data_len, UacryptexHandle *sign_key, const uint8_t *ref_cert, size_t ref_cert_len, const uint8_t *full_crl, size_t full_crl_len, const uint8_t *delta_crl, size_t delta_crl_len, const uint8_t *ocsp_response, size_t ocsp_response_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_sign_cades_a: handle.func(
      'int32 uacryptex_cms_sign_cades_a(const uint8_t *data, size_t data_len, UacryptexHandle *sign_key, const uint8_t *ref_cert, size_t ref_cert_len, const uint8_t *full_crl, size_t full_crl_len, const uint8_t *delta_crl, size_t delta_crl_len, const uint8_t *ocsp_response, size_t ocsp_response_len, UacryptexHandle *tsa_key, const uint8_t *serial, size_t serial_len, int64 current_time, const char *policy_oid, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_verify: handle.func(
      'int32 uacryptex_cms_verify(const uint8_t *data, size_t data_len, const uint8_t *cms, size_t cms_len, UacryptexError *err)'
    ),
    uacryptex_cms_envelop_encrypt: handle.func(
      'int32 uacryptex_cms_envelop_encrypt(const uint8_t *data, size_t data_len, UacryptexHandle *originator_key, const uint8_t *recipient_cert, size_t recipient_cert_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_cms_envelop_decrypt: handle.func(
      'int32 uacryptex_cms_envelop_decrypt(const uint8_t *cms, size_t cms_len, const uint8_t *external, size_t external_len, const uint8_t *originator_cert, size_t originator_cert_len, UacryptexHandle *recipient_key, const uint8_t *recipient_cert, size_t recipient_cert_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_digest: handle.func(
      'int32 uacryptex_digest(const uint8_t *data, size_t data_len, const uint8_t *algorithm_aid, size_t algorithm_aid_len, const uint8_t *cert, size_t cert_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_sign_data: handle.func(
      'int32 uacryptex_sign_data(const uint8_t *data, size_t data_len, UacryptexHandle *key, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_pkcs8_open: handle.func(
      'int32 uacryptex_pkcs8_open(const uint8_t *der, size_t der_len, const uint8_t *cert, size_t cert_len, _Out_ UacryptexHandle **out, UacryptexError *err)'
    ),
    uacryptex_verify_hash: handle.func(
      'int32 uacryptex_verify_hash(const uint8_t *digest, size_t digest_len, const uint8_t *signature, size_t signature_len, const uint8_t *cert, size_t cert_len, UacryptexError *err)'
    ),
    uacryptex_verify_data: handle.func(
      'int32 uacryptex_verify_data(const uint8_t *data, size_t data_len, const uint8_t *signature, size_t signature_len, const uint8_t *cert, size_t cert_len, UacryptexError *err)'
    ),
    uacryptex_cert_verify: handle.func(
      'int32 uacryptex_cert_verify(const uint8_t *cert, size_t cert_len, const uint8_t *issuer_cert, size_t issuer_cert_len, UacryptexError *err)'
    ),
    uacryptex_cert_check_validity: handle.func(
      'int32 uacryptex_cert_check_validity(const uint8_t *cert, size_t cert_len, int64 unix_secs, UacryptexError *err)'
    ),
    uacryptex_cert_spki: handle.func(
      'int32 uacryptex_cert_spki(const uint8_t *cert, size_t cert_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_crl_verify: handle.func(
      'int32 uacryptex_crl_verify(const uint8_t *crl, size_t crl_len, const uint8_t *issuer_cert, size_t issuer_cert_len, UacryptexError *err)'
    ),
    uacryptex_crl_check_cert: handle.func(
      'int32 uacryptex_crl_check_cert(const uint8_t *crl, size_t crl_len, const uint8_t *issuer_cert, size_t issuer_cert_len, const uint8_t *cert, size_t cert_len, _Out_ int32 *revoked, UacryptexError *err)'
    ),
    uacryptex_pkcs12_certificate_count: handle.func(
      'int32 uacryptex_pkcs12_certificate_count(UacryptexHandle *store, _Out_ size_t *count, UacryptexError *err)'
    ),
    uacryptex_pkcs12_get_certificate: handle.func(
      'int32 uacryptex_pkcs12_get_certificate(UacryptexHandle *store, size_t index, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_ocsp_request_from_cert: handle.func(
      'int32 uacryptex_ocsp_request_from_cert(const uint8_t *root_cert, size_t root_cert_len, const uint8_t *user_cert, size_t user_cert_len, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_ocsp_request_generate: handle.func(
      'int32 uacryptex_ocsp_request_generate(const uint8_t *root_cert, size_t root_cert_len, const uint8_t *user_cert, size_t user_cert_len, UacryptexHandle *requestor_key, const uint8_t *ocsp_responder_cert, size_t ocsp_responder_cert_len, const uint8_t *nonce, size_t nonce_len, int32 include_nonce, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_ocsp_response_verify: handle.func(
      'int32 uacryptex_ocsp_response_verify(const uint8_t *response, size_t response_len, const uint8_t *ocsp_responder_cert, size_t ocsp_responder_cert_len, UacryptexError *err)'
    ),
    uacryptex_ocsp_response_validate: handle.func(
      'int32 uacryptex_ocsp_response_validate(const uint8_t *request, size_t request_len, const uint8_t *response, size_t response_len, const uint8_t *root_cert, size_t root_cert_len, int64 current_time, int32 timeout_minutes, UacryptexError *err)'
    ),
    uacryptex_ocsp_response_generate: handle.func(
      'int32 uacryptex_ocsp_response_generate(const uint8_t *request, size_t request_len, const uint8_t *root_cert, size_t root_cert_len, const uint8_t *user_cert, size_t user_cert_len, const uint8_t *full_crl, size_t full_crl_len, const uint8_t *delta_crl, size_t delta_crl_len, UacryptexHandle *ocsp_key, int64 current_time, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_tsp_request_from_data: handle.func(
      'int32 uacryptex_tsp_request_from_data(const uint8_t *data, size_t data_len, const char *policy_oid, int32 cert_req, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_tsp_response_verify: handle.func(
      'int32 uacryptex_tsp_response_verify(const uint8_t *response, size_t response_len, const uint8_t *tsa_cert, size_t tsa_cert_len, UacryptexError *err)'
    ),
    uacryptex_tsp_response_generate: handle.func(
      'int32 uacryptex_tsp_response_generate(const uint8_t *request, size_t request_len, UacryptexHandle *key, const uint8_t *serial, size_t serial_len, int64 current_time, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_csr_generate: handle.func(
      'int32 uacryptex_csr_generate(UacryptexHandle *key, const char *subject, const char *dns, const char *email, const char *subject_dir_attr, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_csr_verify: handle.func(
      'int32 uacryptex_csr_verify(const uint8_t *csr, size_t csr_len, UacryptexError *err)'
    ),
    uacryptex_cert_generate: handle.func(
      'int32 uacryptex_cert_generate(UacryptexHandle *ca_key, const uint8_t *csr, size_t csr_len, uint8_t version, const uint8_t *serial, size_t serial_len, int64 not_before, int64 not_after, int32 self_signed, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_crl_generate: handle.func(
      'int32 uacryptex_crl_generate(UacryptexHandle *ca_key, const uint8_t *previous_crl, size_t previous_crl_len, int32 crl_type, int64 diff_next_update_secs, const uint8_t *merge_delta_crl, size_t merge_delta_crl_len, const uint8_t *revoke_serial, size_t revoke_serial_len, const char *template_name, const char *description, _Out_ UacryptexBuf *out, UacryptexError *err)'
    ),
    uacryptex_dstu4145_verify_pb: handle.func(
      'int32 uacryptex_dstu4145_verify_pb(const uint32_t *f, size_t f_len, int a, const uint8_t *b, size_t b_len, const uint8_t *n, size_t n_len, const uint8_t *gx, size_t gx_len, const uint8_t *gy, size_t gy_len, const uint8_t *qx, size_t qx_len, const uint8_t *qy, size_t qy_len, const uint8_t *hash, size_t hash_len, const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len, UacryptexError *err)'
    ),
  };
}

function getFns() {
  if (!fn) {
    lib = loadLibrary();
    fn = lib;
  }
  return fn;
}

function initError() {
  const err = {};
  getFns().uacryptex_error_init(err);
  return err;
}

function errorMessage(err) {
  if (!err || !err.message) return '';
  if (typeof err.message === 'string') {
    return err.message.replace(/\0.*$/, '');
  }
  return Buffer.from(err.message).toString('utf8').replace(/\0.*$/, '');
}

function check(code, err) {
  const msg = errorMessage(err);
  const exc = mapNativeError(code, msg);
  if (exc) throw exc;
}

function bufToBytes(outBuf) {
  const fns = getFns();
  if (!outBuf.ptr || outBuf.len === 0) {
    fns.uacryptex_buf_free(outBuf);
    return Buffer.alloc(0);
  }
  const bytes = koffi.decode(outBuf.ptr, 'uint8_t', Number(outBuf.len));
  fns.uacryptex_buf_free(outBuf);
  return Buffer.from(bytes);
}

function asBuffer(data) {
  if (data == null || data.length === 0) return { ptr: null, len: 0 };
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return { ptr: buf, len: buf.length };
}

function version() {
  const out = Buffer.alloc(64);
  const code = getFns().uacryptex_version(out, out.length);
  if (code !== RET_OK) {
    throw new Error(`uacryptex_version failed with code ${code}`);
  }
  const nul = out.indexOf(0);
  return out.toString('utf8', 0, nul >= 0 ? nul : out.length);
}

function signOpen(key, cert) {
  const keyB = asBuffer(key);
  const certB = asBuffer(cert);
  const outPtr = [null];
  const err = initError();
  const code = getFns().uacryptex_sign_open(keyB.ptr, keyB.len, certB.ptr, certB.len, outPtr, err);
  check(code, err);
  return outPtr[0];
}

function pkcs12Open(data, password) {
  const dataB = asBuffer(data);
  const outPtr = [null];
  const err = initError();
  const code = getFns().uacryptex_pkcs12_open(dataB.ptr, dataB.len, password, outPtr, err);
  check(code, err);
  return outPtr[0];
}

function handleFree(handle) {
  if (handle) getFns().uacryptex_handle_free(handle);
}

function setCertificate(handle, cert) {
  const certB = asBuffer(cert);
  const err = initError();
  const code = getFns().uacryptex_pkcs12_set_certificates(handle, certB.ptr, certB.len, err);
  check(code, err);
}

function signHash(handle, digest) {
  const digestB = asBuffer(digest);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_sign_hash(digestB.ptr, digestB.len, handle, out, err);
  check(code, err);
  return bufToBytes(out);
}

function cmsSign(handle, data) {
  const dataB = asBuffer(data);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign(dataB.ptr, dataB.len, handle, out, err);
  check(code, err);
  return bufToBytes(out);
}

function cmsSignCadesT(signKey, tsaKey, data, serial, currentTime, policyOid = null) {
  const dataB = asBuffer(data);
  const serialB = asBuffer(serial);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign_cades_t(
    dataB.ptr,
    dataB.len,
    signKey,
    tsaKey,
    serialB.ptr,
    serialB.len,
    currentTime,
    policyOid,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsSignCadesC(signKey, data, refCert, refCrl) {
  const dataB = asBuffer(data);
  const certB = asBuffer(refCert);
  const crlB = asBuffer(refCrl);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign_cades_c(
    dataB.ptr,
    dataB.len,
    signKey,
    certB.ptr,
    certB.len,
    crlB.ptr,
    crlB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsSignCadesX(signKey, data, refCert, ocspResponse) {
  const dataB = asBuffer(data);
  const certB = asBuffer(refCert);
  const ocspB = asBuffer(ocspResponse);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign_cades_x(
    dataB.ptr,
    dataB.len,
    signKey,
    certB.ptr,
    certB.len,
    ocspB.ptr,
    ocspB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsSignCadesLt(signKey, data, refCert, fullCrl, ocspResponse, deltaCrl = null) {
  const dataB = asBuffer(data);
  const certB = asBuffer(refCert);
  const fullB = asBuffer(fullCrl);
  const deltaB = asBuffer(deltaCrl || Buffer.alloc(0));
  const ocspB = asBuffer(ocspResponse);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign_cades_lt(
    dataB.ptr,
    dataB.len,
    signKey,
    certB.ptr,
    certB.len,
    fullB.ptr,
    fullB.len,
    deltaB.ptr,
    deltaB.len,
    ocspB.ptr,
    ocspB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsSignCadesA(
  signKey,
  tsaKey,
  data,
  refCert,
  fullCrl,
  ocspResponse,
  serial,
  currentTime,
  deltaCrl = null,
  policyOid = null
) {
  const dataB = asBuffer(data);
  const certB = asBuffer(refCert);
  const fullB = asBuffer(fullCrl);
  const deltaB = asBuffer(deltaCrl || Buffer.alloc(0));
  const ocspB = asBuffer(ocspResponse);
  const serialB = asBuffer(serial);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_sign_cades_a(
    dataB.ptr,
    dataB.len,
    signKey,
    certB.ptr,
    certB.len,
    fullB.ptr,
    fullB.len,
    deltaB.ptr,
    deltaB.len,
    ocspB.ptr,
    ocspB.len,
    tsaKey,
    serialB.ptr,
    serialB.len,
    currentTime,
    policyOid,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsVerify(data, cms) {
  const dataB = asBuffer(data);
  const cmsB = asBuffer(cms);
  const err = initError();
  const code = getFns().uacryptex_cms_verify(dataB.ptr, dataB.len, cmsB.ptr, cmsB.len, err);
  check(code, err);
}

function cmsEnvelopEncrypt(handle, data, recipientCert) {
  const dataB = asBuffer(data);
  const certB = asBuffer(recipientCert);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_envelop_encrypt(
    dataB.ptr,
    dataB.len,
    handle,
    certB.ptr,
    certB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function cmsEnvelopDecrypt(handle, cms, external, originatorCert, recipientCert) {
  const cmsB = asBuffer(cms);
  const extB = asBuffer(external);
  const origB = asBuffer(originatorCert);
  const rcptB = asBuffer(recipientCert);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cms_envelop_decrypt(
    cmsB.ptr,
    cmsB.len,
    extB.ptr,
    extB.len,
    origB.ptr,
    origB.len,
    handle,
    rcptB.ptr,
    rcptB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function digest(data, algorithmAid, cert) {
  const dataB = asBuffer(data);
  const aidB = asBuffer(algorithmAid);
  const certB = asBuffer(cert);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_digest(
    dataB.ptr,
    dataB.len,
    aidB.ptr,
    aidB.len,
    certB.ptr,
    certB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function signData(handle, data) {
  const dataB = asBuffer(data);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_sign_data(dataB.ptr, dataB.len, handle, out, err);
  check(code, err);
  return bufToBytes(out);
}

function pkcs8Open(der, cert) {
  const derB = asBuffer(der);
  const certB = asBuffer(cert);
  const outPtr = [null];
  const err = initError();
  const code = getFns().uacryptex_pkcs8_open(derB.ptr, derB.len, certB.ptr, certB.len, outPtr, err);
  check(code, err);
  return outPtr[0];
}

function verifyHash(digest, signature, cert) {
  const digestB = asBuffer(digest);
  const sigB = asBuffer(signature);
  const certB = asBuffer(cert);
  const err = initError();
  const code = getFns().uacryptex_verify_hash(
    digestB.ptr,
    digestB.len,
    sigB.ptr,
    sigB.len,
    certB.ptr,
    certB.len,
    err
  );
  check(code, err);
}

function verifyData(data, signature, cert) {
  const dataB = asBuffer(data);
  const sigB = asBuffer(signature);
  const certB = asBuffer(cert);
  const err = initError();
  const code = getFns().uacryptex_verify_data(
    dataB.ptr,
    dataB.len,
    sigB.ptr,
    sigB.len,
    certB.ptr,
    certB.len,
    err
  );
  check(code, err);
}

function certVerify(cert, issuerCert) {
  const certB = asBuffer(cert);
  const issuerB = asBuffer(issuerCert);
  const err = initError();
  const code = getFns().uacryptex_cert_verify(
    certB.ptr,
    certB.len,
    issuerB.ptr,
    issuerB.len,
    err
  );
  check(code, err);
}

function certCheckValidity(cert, unixSecs = 0) {
  const certB = asBuffer(cert);
  const err = initError();
  const code = getFns().uacryptex_cert_check_validity(certB.ptr, certB.len, unixSecs, err);
  check(code, err);
}

function certSpki(cert) {
  const certB = asBuffer(cert);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cert_spki(certB.ptr, certB.len, out, err);
  check(code, err);
  return bufToBytes(out);
}

function crlVerify(crl, issuerCert) {
  const crlB = asBuffer(crl);
  const issuerB = asBuffer(issuerCert);
  const err = initError();
  const code = getFns().uacryptex_crl_verify(crlB.ptr, crlB.len, issuerB.ptr, issuerB.len, err);
  check(code, err);
}

function crlCheckCert(crl, issuerCert, cert) {
  const crlB = asBuffer(crl);
  const issuerB = asBuffer(issuerCert);
  const certB = asBuffer(cert);
  const revoked = [0];
  const err = initError();
  const code = getFns().uacryptex_crl_check_cert(
    crlB.ptr,
    crlB.len,
    issuerB.ptr,
    issuerB.len,
    certB.ptr,
    certB.len,
    revoked,
    err
  );
  check(code, err);
  return revoked[0] !== 0;
}

function pkcs12CertificateCount(handle) {
  const count = [0];
  const err = initError();
  const code = getFns().uacryptex_pkcs12_certificate_count(handle, count, err);
  check(code, err);
  return Number(count[0]);
}

function pkcs12GetCertificate(handle, index) {
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_pkcs12_get_certificate(handle, index, out, err);
  check(code, err);
  return bufToBytes(out);
}

function ocspRequestFromCert(rootCert, userCert) {
  const rootB = asBuffer(rootCert);
  const userB = asBuffer(userCert);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_ocsp_request_from_cert(
    rootB.ptr,
    rootB.len,
    userB.ptr,
    userB.len,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function ocspRequestGenerate(
  rootCert,
  userCert,
  requestorKey,
  ocspResponderCert,
  nonce,
  includeNonce = true
) {
  const rootB = asBuffer(rootCert);
  const userB = asBuffer(userCert);
  const ocspB = asBuffer(ocspResponderCert);
  const nonceB = asBuffer(nonce);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_ocsp_request_generate(
    rootB.ptr,
    rootB.len,
    userB.ptr,
    userB.len,
    requestorKey || null,
    ocspB.ptr,
    ocspB.len,
    nonceB.ptr,
    nonceB.len,
    includeNonce ? 1 : 0,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function ocspResponseVerify(response, ocspResponderCert) {
  const respB = asBuffer(response);
  const certB = asBuffer(ocspResponderCert);
  const err = initError();
  const code = getFns().uacryptex_ocsp_response_verify(respB.ptr, respB.len, certB.ptr, certB.len, err);
  check(code, err);
}

function ocspResponseValidate(request, response, rootCert, currentTime, timeoutMinutes) {
  const reqB = asBuffer(request);
  const respB = asBuffer(response);
  const rootB = asBuffer(rootCert);
  const err = initError();
  const code = getFns().uacryptex_ocsp_response_validate(
    reqB.ptr,
    reqB.len,
    respB.ptr,
    respB.len,
    rootB.ptr,
    rootB.len,
    currentTime,
    timeoutMinutes,
    err
  );
  check(code, err);
}

function ocspResponseGenerate(handle, request, rootCert, userCert, fullCrl, deltaCrl, currentTime) {
  const reqB = asBuffer(request);
  const rootB = asBuffer(rootCert);
  const userB = asBuffer(userCert);
  const fullB = asBuffer(fullCrl);
  const deltaB = asBuffer(deltaCrl);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_ocsp_response_generate(
    reqB.ptr,
    reqB.len,
    rootB.ptr,
    rootB.len,
    userB.ptr,
    userB.len,
    fullB.ptr,
    fullB.len,
    deltaB.ptr,
    deltaB.len,
    handle,
    currentTime,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function tspRequestFromData(data, policyOid, certReq = true) {
  const dataB = asBuffer(data);
  const policy = policyOid || null;
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_tsp_request_from_data(
    dataB.ptr,
    dataB.len,
    policy,
    certReq ? 1 : 0,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function tspResponseVerify(response, tsaCert) {
  const respB = asBuffer(response);
  const certB = asBuffer(tsaCert);
  const err = initError();
  const code = getFns().uacryptex_tsp_response_verify(respB.ptr, respB.len, certB.ptr, certB.len, err);
  check(code, err);
}

function tspResponseGenerate(handle, request, serial, currentTime) {
  const reqB = asBuffer(request);
  const serialB = asBuffer(serial);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_tsp_response_generate(
    reqB.ptr,
    reqB.len,
    handle,
    serialB.ptr,
    serialB.len,
    currentTime,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function csrGenerate(handle, subject, dns, email, subjectDirAttr) {
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_csr_generate(handle, subject, dns || null, email || null, subjectDirAttr || null, out, err);
  check(code, err);
  return bufToBytes(out);
}

function csrVerify(csr) {
  const csrB = asBuffer(csr);
  const err = initError();
  const code = getFns().uacryptex_csr_verify(csrB.ptr, csrB.len, err);
  check(code, err);
}

function certGenerate(handle, csr, version, serial, notBefore, notAfter, selfSigned) {
  const csrB = asBuffer(csr);
  const serialB = asBuffer(serial);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_cert_generate(
    handle,
    csrB.ptr,
    csrB.len,
    version,
    serialB.ptr,
    serialB.len,
    notBefore,
    notAfter,
    selfSigned ? 1 : 0,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function crlGenerate(
  handle,
  previousCrl,
  crlType,
  diffNextUpdateSecs,
  mergeDeltaCrl,
  revokeSerial,
  templateName,
  description
) {
  const prevB = asBuffer(previousCrl);
  const mergeB = asBuffer(mergeDeltaCrl);
  const serialB = asBuffer(revokeSerial);
  const out = {};
  const err = initError();
  const code = getFns().uacryptex_crl_generate(
    handle,
    prevB.ptr,
    prevB.len,
    crlType,
    diffNextUpdateSecs,
    mergeB.ptr,
    mergeB.len,
    serialB.ptr,
    serialB.len,
    templateName || null,
    description || null,
    out,
    err
  );
  check(code, err);
  return bufToBytes(out);
}

function dstu4145VerifyPb(f, a, b, n, gx, gy, qx, qy, hash, r, s) {
  const fArr = Uint32Array.from(f);
  const bB = asBuffer(b);
  const nB = asBuffer(n);
  const gxB = asBuffer(gx);
  const gyB = asBuffer(gy);
  const qxB = asBuffer(qx);
  const qyB = asBuffer(qy);
  const hashB = asBuffer(hash);
  const rB = asBuffer(r);
  const sB = asBuffer(s);
  const err = initError();
  const code = getFns().uacryptex_dstu4145_verify_pb(
    fArr,
    fArr.length,
    a,
    bB.ptr,
    bB.len,
    nB.ptr,
    nB.len,
    gxB.ptr,
    gxB.len,
    gyB.ptr,
    gyB.len,
    qxB.ptr,
    qxB.len,
    qyB.ptr,
    qyB.len,
    hashB.ptr,
    hashB.len,
    rB.ptr,
    rB.len,
    sB.ptr,
    sB.len,
    err
  );
  check(code, err);
}

module.exports = {
  version,
  signOpen,
  pkcs12Open,
  handleFree,
  setCertificate,
  signHash,
  signData,
  pkcs8Open,
  digest,
  verifyHash,
  verifyData,
  certVerify,
  certCheckValidity,
  certSpki,
  crlVerify,
  crlCheckCert,
  pkcs12CertificateCount,
  pkcs12GetCertificate,
  ocspRequestFromCert,
  ocspRequestGenerate,
  ocspResponseVerify,
  ocspResponseValidate,
  ocspResponseGenerate,
  tspRequestFromData,
  tspResponseVerify,
  tspResponseGenerate,
  csrGenerate,
  csrVerify,
  certGenerate,
  crlGenerate,
  dstu4145VerifyPb,
  cmsSign,
  cmsSignCadesT,
  cmsSignCadesC,
  cmsSignCadesX,
  cmsSignCadesLt,
  cmsSignCadesA,
  cmsVerify,
  cmsEnvelopEncrypt,
  cmsEnvelopDecrypt,
};
