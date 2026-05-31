package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// OcspRequestFromCert builds an OCSP request for userCert issued by rootCert.
func OcspRequestFromCert(rootCert, userCert []byte) ([]byte, error) {
	out, err := native.OcspRequestFromCert(rootCert, userCert)
	return out, fromNative(err)
}

// OcspRequestGenerate builds a signed or unsigned OCSP request.
// requestorKey nil → unsigned; ocspResponderCert optional for signed chain.
func OcspRequestGenerate(rootCert, userCert []byte, requestorKey *PrivateKey, ocspResponderCert, nonce []byte, includeNonce bool) ([]byte, error) {
	var h *native.Handle
	if requestorKey != nil {
		h = requestorKey.handle
	}
	out, err := native.OcspRequestGenerate(rootCert, userCert, h, ocspResponderCert, nonce, includeNonce)
	return out, fromNative(err)
}

// OcspRequestGenerate on requestor private key (signed OCSP request).
func (k *PrivateKey) OcspRequestGenerate(rootCert, userCert []byte, ocspResponderCert, nonce []byte, includeNonce bool) ([]byte, error) {
	return OcspRequestGenerate(rootCert, userCert, k, ocspResponderCert, nonce, includeNonce)
}

// OcspRequestVerify verifies a signed OCSP request.
func OcspRequestVerify(request, requestorCert []byte) error {
	return fromNative(native.OcspRequestVerify(request, requestorCert))
}

// OcspResponseVerify verifies OCSP response signature.
func OcspResponseVerify(response, ocspResponderCert []byte) error {
	return fromNative(native.OcspResponseVerify(response, ocspResponderCert))
}

// OcspResponseValidate checks OCSP response freshness and nextUpdate.
func OcspResponseValidate(request, response, rootCert []byte, currentTime int64, timeoutMinutes int32) error {
	return fromNative(native.OcspResponseValidate(request, response, rootCert, currentTime, timeoutMinutes))
}

// OcspResponseGenerate creates an OCSP response (responder private key handle).
func (k *PrivateKey) OcspResponseGenerate(request, rootCert, userCert, fullCRL, deltaCRL []byte, currentTime int64) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.OcspResponseGenerate(request, rootCert, userCert, fullCRL, deltaCRL, currentTime)
	return out, fromNative(err)
}

// TspRequestFromData builds a TSP request from raw data (GOST3411 hash).
func TspRequestFromData(data []byte, policyOID *string, certReq bool) ([]byte, error) {
	out, err := native.TspRequestFromData(data, policyOID, certReq)
	return out, fromNative(err)
}

// TspRequestFromHash builds a TSP request from a precomputed GOST3411 digest.
func TspRequestFromHash(hash []byte, policyOID *string, certReq bool) ([]byte, error) {
	out, err := native.TspRequestFromHash(hash, policyOID, certReq)
	return out, fromNative(err)
}

// TspResponseVerify verifies a TSP response token.
func TspResponseVerify(response, tsaCert []byte) error {
	return fromNative(native.TspResponseVerify(response, tsaCert))
}

// TspResponseGenerate creates a TSP response (TSA private key handle).
func (k *PrivateKey) TspResponseGenerate(request, serial []byte, currentTime int64) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.TspResponseGenerate(request, serial, currentTime)
	return out, fromNative(err)
}

// CsrGenerate creates a PKCS#10 certification request.
func (k *PrivateKey) CsrGenerate(subject, dns, email, subjectDirAttr string) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.CsrGenerate(subject, dns, email, subjectDirAttr)
	return out, fromNative(err)
}

// CsrVerify verifies CSR self-signature.
func CsrVerify(csr []byte) error {
	return fromNative(native.CsrVerify(csr))
}

// GenerateCertificate issues an X.509 certificate from CSR (CA or self-signed key).
func (k *PrivateKey) GenerateCertificate(csr []byte, version byte, serial []byte, notBefore, notAfter int64, selfSigned bool) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.CertGenerate(csr, version, serial, notBefore, notAfter, selfSigned)
	return out, fromNative(err)
}

// CRL type constants for GenerateCRL.
const (
	CRLTypeDelta = native.CRLTypeDelta
	CRLTypeFull  = native.CRLTypeFull
)

// GenerateCRL issues a new CRL from previousCRL using CA private key.
func (k *PrivateKey) GenerateCRL(
	previousCRL []byte,
	crlType int32,
	diffNextUpdateSecs int64,
	mergeDeltaCRL, revokeSerial []byte,
	templateName, description string,
) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.CRLGenerate(
		previousCRL, crlType, diffNextUpdateSecs, mergeDeltaCRL, revokeSerial, templateName, description,
	)
	return out, fromNative(err)
}
