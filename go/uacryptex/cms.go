package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// VerifyCMS verifies a CMS SignedData signature over data.
func VerifyCMS(data, cms []byte) error {
	return fromNative(native.CMSVerify(data, cms))
}

// SignCMS signs data and returns a CMS SignedData structure (CAdES-BES subset).
func SignCMS(data []byte, key *PrivateKey) ([]byte, error) {
	if key == nil || key.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := key.handle.CMSSign(data)
	return cms, fromNative(err)
}

// SignOptions configures CMS signing (reserved for future use).
type SignOptions struct{}

// VerifyOptions configures CMS verification (reserved for future use).
type VerifyOptions struct{}

// VerifyCMSWithOptions verifies CMS with optional settings.
func VerifyCMSWithOptions(data, cms []byte, _ VerifyOptions) error {
	return VerifyCMS(data, cms)
}

// SignCMSWithOptions signs CMS with optional settings.
func SignCMSWithOptions(data []byte, key *PrivateKey, _ SignOptions) ([]byte, error) {
	return SignCMS(data, key)
}

// SignCmsCadesT signs data and returns CAdES-T CMS (BES + timestamp token).
func SignCmsCadesT(data, serial []byte, signKey, tsaKey *PrivateKey, currentTime int64, policyOID *string) ([]byte, error) {
	if signKey == nil || signKey.handle == nil || tsaKey == nil || tsaKey.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := native.CMSSignCadesT(data, serial, signKey.handle, tsaKey.handle, currentTime, policyOID)
	return cms, fromNative(err)
}

// SignCmsCadesC signs data and returns CAdES-C CMS (BES + certificate/revocation refs).
func SignCmsCadesC(data, refCert, refCrl []byte, signKey *PrivateKey) ([]byte, error) {
	if signKey == nil || signKey.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := native.CMSSignCadesC(data, refCert, refCrl, signKey.handle)
	return cms, fromNative(err)
}

// SignCmsCadesX signs data and returns CAdES-X CMS (BES + certificate/revocation values).
func SignCmsCadesX(data, refCert, ocspResponse []byte, signKey *PrivateKey) ([]byte, error) {
	if signKey == nil || signKey.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := native.CMSSignCadesX(data, refCert, ocspResponse, signKey.handle)
	return cms, fromNative(err)
}

// SignCmsCadesLT signs data and returns CAdES-LT CMS (X + embedded validation data).
func SignCmsCadesLT(
	data, refCert, fullCrl, deltaCrl, ocspResponse []byte,
	signKey *PrivateKey,
) ([]byte, error) {
	if signKey == nil || signKey.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := native.CMSSignCadesLT(data, refCert, fullCrl, deltaCrl, ocspResponse, signKey.handle)
	return cms, fromNative(err)
}

// SignCmsCadesA signs data and returns CAdES-A CMS (LT + archive timestamp).
func SignCmsCadesA(
	data, refCert, fullCrl, deltaCrl, ocspResponse, serial []byte,
	signKey, tsaKey *PrivateKey,
	currentTime int64,
	policyOID *string,
) ([]byte, error) {
	if signKey == nil || signKey.handle == nil || tsaKey == nil || tsaKey.handle == nil {
		return nil, ErrInvalidParam
	}
	cms, err := native.CMSSignCadesA(
		data, refCert, fullCrl, deltaCrl, ocspResponse, serial,
		signKey.handle, tsaKey.handle, currentTime, policyOID,
	)
	return cms, fromNative(err)
}
