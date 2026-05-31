'use strict';

const native = require('./native');
const { InvalidParamError } = require('./errors');

const VERSION = '0.1.0';

class PrivateKey {
  constructor(handle, ownsHandle = true) {
    this._handle = handle;
    this._ownsHandle = ownsHandle;
    this._closed = false;
  }

  close() {
    if (this._ownsHandle && !this._closed) {
      native.handleFree(this._handle);
      this._handle = null;
      this._closed = true;
    }
  }

  signHash(digest) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.signHash(this._handle, digest);
  }

  signData(data) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.signData(this._handle, data);
  }

  ocspResponseGenerate(request, rootCert, userCert, fullCrl, deltaCrl, currentTime) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.ocspResponseGenerate(
      this._handle,
      request,
      rootCert,
      userCert,
      fullCrl,
      deltaCrl,
      currentTime
    );
  }

  ocspRequestGenerate(rootCert, userCert, ocspResponderCert, nonce, includeNonce = true) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.ocspRequestGenerate(
      rootCert,
      userCert,
      this._handle,
      ocspResponderCert,
      nonce,
      includeNonce
    );
  }

  tspResponseGenerate(request, serial, currentTime) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.tspResponseGenerate(this._handle, request, serial, currentTime);
  }

  csrGenerate(subject, dns, email, subjectDirAttr) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.csrGenerate(this._handle, subject, dns, email, subjectDirAttr);
  }

  generateCertificate(csr, version, serial, notBefore, notAfter, selfSigned = false) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.certGenerate(this._handle, csr, version, serial, notBefore, notAfter, selfSigned);
  }

  generateCrl(
    previousCrl,
    crlType,
    diffNextUpdateSecs,
    mergeDeltaCrl = null,
    revokeSerial = null,
    templateName = '',
    description = ''
  ) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return native.crlGenerate(
      this._handle,
      previousCrl,
      crlType,
      diffNextUpdateSecs,
      mergeDeltaCrl,
      revokeSerial,
      templateName,
      description
    );
  }

  _nativeHandle() {
    if (this._closed || !this._handle) throw new InvalidParamError('closed private key');
    return this._handle;
  }
}

class Keystore {
  constructor(handle) {
    this._handle = handle;
    this._closed = false;
  }

  close() {
    if (!this._closed) {
      native.handleFree(this._handle);
      this._handle = null;
      this._closed = true;
    }
  }

  setCertificate(cert) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed keystore');
    native.setCertificate(this._handle, cert);
  }

  privateKey() {
    if (this._closed || !this._handle) throw new InvalidParamError('closed keystore');
    return new PrivateKey(this._handle, false);
  }

  certificateCount() {
    if (this._closed || !this._handle) throw new InvalidParamError('closed keystore');
    return native.pkcs12CertificateCount(this._handle);
  }

  getCertificate(index) {
    if (this._closed || !this._handle) throw new InvalidParamError('closed keystore');
    return native.pkcs12GetCertificate(this._handle, index);
  }
}

function libraryVersion() {
  return native.version();
}

function openPrivateKey(key, cert) {
  return new PrivateKey(native.signOpen(key, cert));
}

function openPkcs12(data, password) {
  return new Keystore(native.pkcs12Open(data, password));
}

function openPkcs8(der, cert = null) {
  return new PrivateKey(native.pkcs8Open(der, cert));
}

function digest(data, algorithmAid = null, cert = null) {
  return native.digest(data, algorithmAid, cert);
}

function signData(data, key) {
  return native.signData(key._nativeHandle(), data);
}

function verifyHash(digest, signature, cert) {
  native.verifyHash(digest, signature, cert);
}

function verifyData(data, signature, cert) {
  native.verifyData(data, signature, cert);
}

function verifyCertificate(cert, issuerCert) {
  native.certVerify(cert, issuerCert);
}

function checkCertificateValidity(cert, unixSecs = 0) {
  native.certCheckValidity(cert, unixSecs);
}

function certificateSpki(cert) {
  return native.certSpki(cert);
}

function verifyCrl(crl, issuerCert) {
  native.crlVerify(crl, issuerCert);
}

function isCertificateRevoked(crl, issuerCert, cert) {
  return native.crlCheckCert(crl, issuerCert, cert);
}

const CRL_TYPE_DELTA = 0;
const CRL_TYPE_FULL = 1;

function verifyDstu4145Pb(f, a, b, n, gx, gy, qx, qy, hash, r, s) {
  native.dstu4145VerifyPb(f, a, b, n, gx, gy, qx, qy, hash, r, s);
}

function ocspRequestFromCert(rootCert, userCert) {
  return native.ocspRequestFromCert(rootCert, userCert);
}

function ocspRequestGenerate(rootCert, userCert, requestorKey, ocspResponderCert, nonce, includeNonce) {
  return native.ocspRequestGenerate(
    rootCert,
    userCert,
    requestorKey ? requestorKey._nativeHandle() : null,
    ocspResponderCert,
    nonce,
    includeNonce
  );
}

function ocspResponseVerify(response, ocspResponderCert) {
  native.ocspResponseVerify(response, ocspResponderCert);
}

function ocspResponseValidate(request, response, rootCert, currentTime, timeoutMinutes) {
  native.ocspResponseValidate(request, response, rootCert, currentTime, timeoutMinutes);
}

function tspRequestFromData(data, policyOid = null, certReq = true) {
  return native.tspRequestFromData(data, policyOid, certReq);
}

function tspResponseVerify(response, tsaCert) {
  native.tspResponseVerify(response, tsaCert);
}

function csrVerify(csr) {
  native.csrVerify(csr);
}

function signCms(data, key) {
  return native.cmsSign(key._nativeHandle(), data);
}

function signCmsCadesT(data, signKey, tsaKey, serial, currentTime, policyOid = null) {
  return native.cmsSignCadesT(
    signKey._nativeHandle(),
    tsaKey._nativeHandle(),
    data,
    serial,
    currentTime,
    policyOid
  );
}

function signCmsCadesC(data, signKey, refCert, refCrl) {
  if (!refCert || refCert.length === 0 || !refCrl || refCrl.length === 0) {
    throw new InvalidParamError('reference certificate and CRL required');
  }
  return native.cmsSignCadesC(
    signKey._nativeHandle(),
    data,
    refCert,
    refCrl
  );
}

function signCmsCadesX(data, signKey, refCert, ocspResponse) {
  if (!refCert || refCert.length === 0 || !ocspResponse || ocspResponse.length === 0) {
    throw new InvalidParamError('reference certificate and OCSP response required');
  }
  return native.cmsSignCadesX(
    signKey._nativeHandle(),
    data,
    refCert,
    ocspResponse
  );
}

function signCmsCadesLt(data, signKey, refCert, fullCrl, ocspResponse, deltaCrl = null) {
  if (!refCert || refCert.length === 0 || !fullCrl || fullCrl.length === 0 || !ocspResponse || ocspResponse.length === 0) {
    throw new InvalidParamError('reference certificate, CRL and OCSP response required');
  }
  return native.cmsSignCadesLt(
    signKey._nativeHandle(),
    data,
    refCert,
    fullCrl,
    ocspResponse,
    deltaCrl
  );
}

function signCmsCadesA(
  data,
  signKey,
  tsaKey,
  refCert,
  fullCrl,
  ocspResponse,
  serial,
  currentTime,
  deltaCrl = null,
  policyOid = null
) {
  if (!refCert || refCert.length === 0 || !fullCrl || fullCrl.length === 0 || !ocspResponse || ocspResponse.length === 0) {
    throw new InvalidParamError('reference certificate, CRL and OCSP response required');
  }
  return native.cmsSignCadesA(
    signKey._nativeHandle(),
    tsaKey._nativeHandle(),
    data,
    refCert,
    fullCrl,
    ocspResponse,
    serial,
    currentTime,
    deltaCrl,
    policyOid
  );
}

function verifyCms(data, cms) {
  native.cmsVerify(data, cms);
}

function envelopCms(data, originatorKey, recipientCert) {
  if (!recipientCert || recipientCert.length === 0) {
    throw new InvalidParamError('recipient certificate required');
  }
  return native.cmsEnvelopEncrypt(originatorKey._nativeHandle(), data, recipientCert);
}

function decryptCms(cms, recipientKey, recipientCert, originatorCert = null, external = null) {
  if (!cms || cms.length === 0 || !recipientCert || recipientCert.length === 0) {
    throw new InvalidParamError('cms and recipient certificate required');
  }
  return native.cmsEnvelopDecrypt(
    recipientKey._nativeHandle(),
    cms,
    external,
    originatorCert,
    recipientCert
  );
}

module.exports = {
  VERSION,
  libraryVersion,
  PrivateKey,
  Keystore,
  openPrivateKey,
  openPkcs12,
  openPkcs8,
  digest,
  signData,
  verifyHash,
  verifyData,
  verifyCertificate,
  checkCertificateValidity,
  certificateSpki,
  verifyCrl,
  isCertificateRevoked,
  CRL_TYPE_DELTA,
  CRL_TYPE_FULL,
  verifyDstu4145Pb,
  ocspRequestFromCert,
  ocspRequestGenerate,
  ocspResponseVerify,
  ocspResponseValidate,
  tspRequestFromData,
  tspResponseVerify,
  csrVerify,
  signCms,
  signCmsCadesT,
  signCmsCadesC,
  signCmsCadesX,
  signCmsCadesLt,
  signCmsCadesA,
  verifyCms,
  envelopCms,
  decryptCms,
  ...require('./errors'),
};
