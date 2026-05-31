// Package native wraps the uacryptex C ABI via cgo.
package native

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../include

#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../../native/lib/linux/amd64 -luacryptex_ffi -lm -ldl -lpthread
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../../native/lib/linux/arm64 -luacryptex_ffi -lm -ldl -lpthread
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../../../native/lib/darwin/amd64 -luacryptex_ffi -lm -lpthread
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../../../native/lib/darwin/arm64 -luacryptex_ffi -lm -lpthread
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/../../../native/lib/windows/amd64 -luacryptex_ffi -lws2_32 -luserenv -lntdll -ladvapi32 -lbcrypt

#include "uacryptex.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	RetOK           = 0
	RetMemory       = 1
	RetInvalidParam = 2
	RetVerifyFailed = 3
)

// Handle is an opaque native key or PKCS#12 session.
type Handle struct {
	h *C.UacryptexHandle
}

// Close releases native resources.
func (h *Handle) Close() {
	if h == nil || h.h == nil {
		return
	}
	C.uacryptex_handle_free(h.h)
	h.h = nil
}

func initError() C.UacryptexError {
	var err C.UacryptexError
	C.uacryptex_error_init(&err)
	return err
}

func errorMessage(err *C.UacryptexError) string {
	if err == nil {
		return ""
	}
	return C.GoString(&err.message[0])
}

func freeBuf(buf C.UacryptexBuf) {
	C.uacryptex_buf_free(buf)
}

func bufToBytes(buf C.UacryptexBuf) []byte {
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
	freeBuf(buf)
	return out
}

// Version returns the Rust core version via FFI.
func Version() (string, error) {
	buf := make([]byte, 64)
	rc := C.uacryptex_version((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if rc != RetOK {
		return "", fmt.Errorf("native: uacryptex_version failed with code %d", int(rc))
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n]), nil
}

// SignOpen creates a signing handle from raw private key bytes and a certificate.
func SignOpen(key, cert []byte) (*Handle, error) {
	var out *C.UacryptexHandle
	err := initError()
	rc := C.uacryptex_sign_open(
		bytesPtr(key), C.uintptr_t(len(key)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return &Handle{h: out}, nil
}

// PKCS12Open opens a PKCS#12 container and selects the first private key.
func PKCS12Open(p12 []byte, password string) (*Handle, error) {
	pass := C.CString(password)
	defer C.free(unsafe.Pointer(pass))

	var out *C.UacryptexHandle
	err := initError()
	rc := C.uacryptex_pkcs12_open(
		bytesPtr(p12), C.uintptr_t(len(p12)),
		pass,
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return &Handle{h: out}, nil
}

// SetCertificate attaches an external certificate to a PKCS#12 handle.
func (h *Handle) SetCertificate(cert []byte) error {
	if h == nil || h.h == nil {
		return fmt.Errorf("native: nil handle")
	}
	err := initError()
	rc := C.uacryptex_pkcs12_set_certificates(
		h.h,
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// SignHash signs a precomputed digest.
func (h *Handle) SignHash(hash []byte) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_sign_hash(
		bytesPtr(hash), C.uintptr_t(len(hash)),
		h.h,
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSign builds a CMS SignedData structure.
func (h *Handle) CMSSign(data []byte) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign(
		bytesPtr(data), C.uintptr_t(len(data)),
		h.h,
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSignCadesT builds CAdES-T (BES + signature timestamp token).
func CMSSignCadesT(data, serial []byte, signKey, tsaKey *Handle, currentTime int64, policyOID *string) ([]byte, error) {
	if signKey == nil || signKey.h == nil || tsaKey == nil || tsaKey.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var policyC *C.char
	if policyOID != nil && *policyOID != "" {
		p := C.CString(*policyOID)
		defer C.free(unsafe.Pointer(p))
		policyC = p
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign_cades_t(
		bytesPtr(data), C.uintptr_t(len(data)),
		signKey.h,
		tsaKey.h,
		bytesPtr(serial), C.uintptr_t(len(serial)),
		C.int64_t(currentTime),
		policyC,
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSignCadesC builds CAdES-C (BES + certificate/revocation references).
func CMSSignCadesC(data, refCert, refCrl []byte, signKey *Handle) ([]byte, error) {
	if signKey == nil || signKey.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign_cades_c(
		bytesPtr(data), C.uintptr_t(len(data)),
		signKey.h,
		bytesPtr(refCert), C.uintptr_t(len(refCert)),
		bytesPtr(refCrl), C.uintptr_t(len(refCrl)),
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSignCadesX builds CAdES-X (BES + certificate/revocation values).
func CMSSignCadesX(data, refCert, ocspResponse []byte, signKey *Handle) ([]byte, error) {
	if signKey == nil || signKey.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign_cades_x(
		bytesPtr(data), C.uintptr_t(len(data)),
		signKey.h,
		bytesPtr(refCert), C.uintptr_t(len(refCert)),
		bytesPtr(ocspResponse), C.uintptr_t(len(ocspResponse)),
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSignCadesLT builds CAdES-LT (X + validation certificates/CRLs in SignedData).
func CMSSignCadesLT(data, refCert, fullCrl, deltaCrl, ocspResponse []byte, signKey *Handle) ([]byte, error) {
	if signKey == nil || signKey.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign_cades_lt(
		bytesPtr(data), C.uintptr_t(len(data)),
		signKey.h,
		bytesPtr(refCert), C.uintptr_t(len(refCert)),
		bytesPtr(fullCrl), C.uintptr_t(len(fullCrl)),
		bytesPtr(deltaCrl), C.uintptr_t(len(deltaCrl)),
		bytesPtr(ocspResponse), C.uintptr_t(len(ocspResponse)),
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSSignCadesA builds CAdES-A (LT + archive timestamp).
func CMSSignCadesA(
	data, refCert, fullCrl, deltaCrl, ocspResponse, serial []byte,
	signKey, tsaKey *Handle,
	currentTime int64,
	policyOID *string,
) ([]byte, error) {
	if signKey == nil || signKey.h == nil || tsaKey == nil || tsaKey.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var policyC *C.char
	if policyOID != nil && *policyOID != "" {
		p := C.CString(*policyOID)
		defer C.free(unsafe.Pointer(p))
		policyC = p
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_sign_cades_a(
		bytesPtr(data), C.uintptr_t(len(data)),
		signKey.h,
		bytesPtr(refCert), C.uintptr_t(len(refCert)),
		bytesPtr(fullCrl), C.uintptr_t(len(fullCrl)),
		bytesPtr(deltaCrl), C.uintptr_t(len(deltaCrl)),
		bytesPtr(ocspResponse), C.uintptr_t(len(ocspResponse)),
		tsaKey.h,
		bytesPtr(serial), C.uintptr_t(len(serial)),
		C.int64_t(currentTime),
		policyC,
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSVerify verifies a CMS SignedData signature.
func CMSVerify(data, cms []byte) error {
	err := initError()
	rc := C.uacryptex_cms_verify(
		bytesPtr(data), C.uintptr_t(len(data)),
		bytesPtr(cms), C.uintptr_t(len(cms)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// CMSEnvelopEncrypt builds CMS EnvelopedData for recipientCert using originatorKey.
func (h *Handle) CMSEnvelopEncrypt(data, recipientCert []byte) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_envelop_encrypt(
		bytesPtr(data), C.uintptr_t(len(data)),
		h.h,
		bytesPtr(recipientCert), C.uintptr_t(len(recipientCert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CMSEnvelopDecrypt decrypts CMS EnvelopedData.
// Pass nil originatorCert when embedded in CMS; nil external when ciphertext is embedded.
func (h *Handle) CMSEnvelopDecrypt(cms, external, originatorCert, recipientCert []byte) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cms_envelop_decrypt(
		bytesPtr(cms), C.uintptr_t(len(cms)),
		bytesPtr(external), C.uintptr_t(len(external)),
		bytesPtr(originatorCert), C.uintptr_t(len(originatorCert)),
		h.h,
		bytesPtr(recipientCert), C.uintptr_t(len(recipientCert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// Digest computes GOST3411 (default) or cert/aid-selected hash.
func Digest(data, algorithmAid, cert []byte) ([]byte, error) {
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_digest(
		bytesPtr(data), C.uintptr_t(len(data)),
		bytesPtr(algorithmAid), C.uintptr_t(len(algorithmAid)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// SignData signs raw data (hash-then-sign).
func (h *Handle) SignData(data []byte) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_sign_data(
		bytesPtr(data), C.uintptr_t(len(data)),
		h.h,
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// PKCS8Open opens a signing handle from PKCS#8 DER and optional certificate.
func PKCS8Open(der, cert []byte) (*Handle, error) {
	var out *C.UacryptexHandle
	err := initError()
	rc := C.uacryptex_pkcs8_open(
		bytesPtr(der), C.uintptr_t(len(der)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return &Handle{h: out}, nil
}

// VerifyHash verifies a detached signature over a digest.
func VerifyHash(digest, signature, cert []byte) error {
	err := initError()
	rc := C.uacryptex_verify_hash(
		bytesPtr(digest), C.uintptr_t(len(digest)),
		bytesPtr(signature), C.uintptr_t(len(signature)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// VerifyData verifies a detached signature over raw data.
func VerifyData(data, signature, cert []byte) error {
	err := initError()
	rc := C.uacryptex_verify_data(
		bytesPtr(data), C.uintptr_t(len(data)),
		bytesPtr(signature), C.uintptr_t(len(signature)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// CertVerify verifies a certificate using its issuer certificate.
func CertVerify(cert, issuerCert []byte) error {
	err := initError()
	rc := C.uacryptex_cert_verify(
		bytesPtr(cert), C.uintptr_t(len(cert)),
		bytesPtr(issuerCert), C.uintptr_t(len(issuerCert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// CertCheckValidity checks notBefore/notAfter (unixSecs 0 = now).
func CertCheckValidity(cert []byte, unixSecs int64) error {
	err := initError()
	rc := C.uacryptex_cert_check_validity(
		bytesPtr(cert), C.uintptr_t(len(cert)),
		C.int64_t(unixSecs),
		&err,
	)
	return statusError(int32(rc), &err)
}

// CertSPKI returns SubjectPublicKeyInfo DER from a certificate.
func CertSPKI(cert []byte) ([]byte, error) {
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_cert_spki(
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&out,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CRLVerify verifies a CRL signature using the issuer certificate.
func CRLVerify(crl, issuerCert []byte) error {
	err := initError()
	rc := C.uacryptex_crl_verify(
		bytesPtr(crl), C.uintptr_t(len(crl)),
		bytesPtr(issuerCert), C.uintptr_t(len(issuerCert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// CRLCheckCert returns true when cert is revoked by crl.
func CRLCheckCert(crl, issuerCert, cert []byte) (bool, error) {
	var revoked C.int32_t
	err := initError()
	rc := C.uacryptex_crl_check_cert(
		bytesPtr(crl), C.uintptr_t(len(crl)),
		bytesPtr(issuerCert), C.uintptr_t(len(issuerCert)),
		bytesPtr(cert), C.uintptr_t(len(cert)),
		&revoked,
		&err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return false, e
	}
	return revoked != 0, nil
}

// CertificateCount returns stored X.509 certificates in a PKCS#12 handle.
func (h *Handle) CertificateCount() (int, error) {
	if h == nil || h.h == nil {
		return 0, fmt.Errorf("native: nil handle")
	}
	var count C.uintptr_t
	err := initError()
	rc := C.uacryptex_pkcs12_certificate_count(h.h, &count, &err)
	if e := statusError(int32(rc), &err); e != nil {
		return 0, e
	}
	return int(count), nil
}

// GetCertificate returns certificate DER at index from PKCS#12.
func (h *Handle) GetCertificate(index int) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_pkcs12_get_certificate(h.h, C.uintptr_t(index), &out, &err)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// OcspRequestFromCert builds a signed OCSP request for userCert issued by rootCert.
func OcspRequestFromCert(rootCert, userCert []byte) ([]byte, error) {
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_ocsp_request_from_cert(
		bytesPtr(rootCert), C.uintptr_t(len(rootCert)),
		bytesPtr(userCert), C.uintptr_t(len(userCert)),
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func OcspRequestGenerate(
	rootCert, userCert []byte,
	requestorKey *Handle,
	ocspResponderCert, nonce []byte,
	includeNonce bool,
) ([]byte, error) {
	var out C.UacryptexBuf
	err := initError()
	var key *C.UacryptexHandle
	if requestorKey != nil {
		key = requestorKey.h
	}
	inc := C.int32_t(0)
	if includeNonce {
		inc = 1
	}
	rc := C.uacryptex_ocsp_request_generate(
		bytesPtr(rootCert), C.uintptr_t(len(rootCert)),
		bytesPtr(userCert), C.uintptr_t(len(userCert)),
		key,
		bytesPtr(ocspResponderCert), C.uintptr_t(len(ocspResponderCert)),
		bytesPtr(nonce), C.uintptr_t(len(nonce)),
		inc,
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func OcspRequestVerify(request, requestorCert []byte) error {
	err := initError()
	rc := C.uacryptex_ocsp_request_verify(
		bytesPtr(request), C.uintptr_t(len(request)),
		bytesPtr(requestorCert), C.uintptr_t(len(requestorCert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

func OcspResponseVerify(response, ocspResponderCert []byte) error {
	err := initError()
	rc := C.uacryptex_ocsp_response_verify(
		bytesPtr(response), C.uintptr_t(len(response)),
		bytesPtr(ocspResponderCert), C.uintptr_t(len(ocspResponderCert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

func OcspResponseValidate(request, response, rootCert []byte, currentTime int64, timeoutMinutes int32) error {
	err := initError()
	rc := C.uacryptex_ocsp_response_validate(
		bytesPtr(request), C.uintptr_t(len(request)),
		bytesPtr(response), C.uintptr_t(len(response)),
		bytesPtr(rootCert), C.uintptr_t(len(rootCert)),
		C.int64_t(currentTime), C.int32_t(timeoutMinutes),
		&err,
	)
	return statusError(int32(rc), &err)
}

func (h *Handle) OcspResponseGenerate(request, rootCert, userCert, fullCRL, deltaCRL []byte, currentTime int64) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_ocsp_response_generate(
		bytesPtr(request), C.uintptr_t(len(request)),
		bytesPtr(rootCert), C.uintptr_t(len(rootCert)),
		bytesPtr(userCert), C.uintptr_t(len(userCert)),
		bytesPtr(fullCRL), C.uintptr_t(len(fullCRL)),
		bytesPtr(deltaCRL), C.uintptr_t(len(deltaCRL)),
		h.h, C.int64_t(currentTime), &out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func TspRequestFromData(data []byte, policyOID *string, certReq bool) ([]byte, error) {
	var policy *C.char
	if policyOID != nil {
		c := C.CString(*policyOID)
		defer C.free(unsafe.Pointer(c))
		policy = c
	}
	var out C.UacryptexBuf
	err := initError()
	certReqInt := C.int32_t(0)
	if certReq {
		certReqInt = 1
	}
	rc := C.uacryptex_tsp_request_from_data(
		bytesPtr(data), C.uintptr_t(len(data)),
		policy, certReqInt, &out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func TspRequestFromHash(hash []byte, policyOID *string, certReq bool) ([]byte, error) {
	var policy *C.char
	if policyOID != nil {
		c := C.CString(*policyOID)
		defer C.free(unsafe.Pointer(c))
		policy = c
	}
	var out C.UacryptexBuf
	err := initError()
	certReqInt := C.int32_t(0)
	if certReq {
		certReqInt = 1
	}
	rc := C.uacryptex_tsp_request_from_hash(
		bytesPtr(hash), C.uintptr_t(len(hash)),
		policy, certReqInt, &out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func TspResponseVerify(response, tsaCert []byte) error {
	err := initError()
	rc := C.uacryptex_tsp_response_verify(
		bytesPtr(response), C.uintptr_t(len(response)),
		bytesPtr(tsaCert), C.uintptr_t(len(tsaCert)),
		&err,
	)
	return statusError(int32(rc), &err)
}

func (h *Handle) TspResponseGenerate(request, serial []byte, currentTime int64) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_tsp_response_generate(
		bytesPtr(request), C.uintptr_t(len(request)),
		h.h,
		bytesPtr(serial), C.uintptr_t(len(serial)),
		C.int64_t(currentTime), &out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func (h *Handle) CsrGenerate(subject, dns, email, subjectDirAttr string) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	subj := C.CString(subject)
	defer C.free(unsafe.Pointer(subj))
	var dnsC, emailC, sdaC *C.char
	if dns != "" {
		d := C.CString(dns)
		defer C.free(unsafe.Pointer(d))
		dnsC = d
	}
	if email != "" {
		e := C.CString(email)
		defer C.free(unsafe.Pointer(e))
		emailC = e
	}
	if subjectDirAttr != "" {
		a := C.CString(subjectDirAttr)
		defer C.free(unsafe.Pointer(a))
		sdaC = a
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_csr_generate(h.h, subj, dnsC, emailC, sdaC, &out, &err)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func CsrVerify(csr []byte) error {
	err := initError()
	rc := C.uacryptex_csr_verify(bytesPtr(csr), C.uintptr_t(len(csr)), &err)
	return statusError(int32(rc), &err)
}

func (h *Handle) CertGenerate(csr []byte, version byte, serial []byte, notBefore, notAfter int64, selfSigned bool) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var out C.UacryptexBuf
	err := initError()
	self := C.int32_t(0)
	if selfSigned {
		self = 1
	}
	rc := C.uacryptex_cert_generate(
		h.h,
		bytesPtr(csr), C.uintptr_t(len(csr)),
		C.uint8_t(version),
		bytesPtr(serial), C.uintptr_t(len(serial)),
		C.int64_t(notBefore), C.int64_t(notAfter),
		self,
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

// CRLTypeDelta / CRLTypeFull match FFI `crl_type` values.
const (
	CRLTypeDelta = 0
	CRLTypeFull  = 1
)

func (h *Handle) CRLGenerate(
	previousCRL []byte,
	crlType int32,
	diffNextUpdateSecs int64,
	mergeDeltaCRL, revokeSerial []byte,
	templateName, description string,
) ([]byte, error) {
	if h == nil || h.h == nil {
		return nil, fmt.Errorf("native: nil handle")
	}
	var tmplC, descC *C.char
	if templateName != "" {
		t := C.CString(templateName)
		defer C.free(unsafe.Pointer(t))
		tmplC = t
	}
	if description != "" {
		d := C.CString(description)
		defer C.free(unsafe.Pointer(d))
		descC = d
	}
	var out C.UacryptexBuf
	err := initError()
	rc := C.uacryptex_crl_generate(
		h.h,
		bytesPtr(previousCRL), C.uintptr_t(len(previousCRL)),
		C.int32_t(crlType),
		C.int64_t(diffNextUpdateSecs),
		bytesPtr(mergeDeltaCRL), C.uintptr_t(len(mergeDeltaCRL)),
		bytesPtr(revokeSerial), C.uintptr_t(len(revokeSerial)),
		tmplC, descC,
		&out, &err,
	)
	if e := statusError(int32(rc), &err); e != nil {
		return nil, e
	}
	return bufToBytes(out), nil
}

func Dstu4145VerifyPB(f []uint32, a int32, b, n, gx, gy, qx, qy, hash, r, s []byte) error {
	if len(f) == 0 {
		return fmt.Errorf("native: field polynomial f is empty")
	}
	err := initError()
	rc := C.uacryptex_dstu4145_verify_pb(
		(*C.uint32_t)(unsafe.Pointer(&f[0])), C.uintptr_t(len(f)),
		C.int(a),
		bytesPtr(b), C.uintptr_t(len(b)),
		bytesPtr(n), C.uintptr_t(len(n)),
		bytesPtr(gx), C.uintptr_t(len(gx)),
		bytesPtr(gy), C.uintptr_t(len(gy)),
		bytesPtr(qx), C.uintptr_t(len(qx)),
		bytesPtr(qy), C.uintptr_t(len(qy)),
		bytesPtr(hash), C.uintptr_t(len(hash)),
		bytesPtr(r), C.uintptr_t(len(r)),
		bytesPtr(s), C.uintptr_t(len(s)),
		&err,
	)
	return statusError(int32(rc), &err)
}

// NativeError carries an FFI status code and message without mapping to sentinels.
type NativeError struct {
	Code    int32
	Message string
}

func (e *NativeError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("native: error code %d", e.Code)
	}
	return "native: " + e.Message
}

func statusError(code int32, err *C.UacryptexError) error {
	if code == RetOK {
		return nil
	}
	return &NativeError{Code: code, Message: errorMessage(err)}
}

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
