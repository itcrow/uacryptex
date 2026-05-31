package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// Digest computes GOST3411 (default) or cert/AlgorithmIdentifier-selected hash.
func Digest(data []byte, algorithmAid, cert []byte) ([]byte, error) {
	out, err := native.Digest(data, algorithmAid, cert)
	return out, fromNative(err)
}

// SignData signs raw data (hash-then-sign).
func (k *PrivateKey) SignData(data []byte) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	sig, err := k.handle.SignData(data)
	return sig, fromNative(err)
}

// OpenPKCS8 opens a signing key from PKCS#8 PrivateKeyInfo DER and optional certificate.
func OpenPKCS8(der, cert []byte) (*PrivateKey, error) {
	h, err := native.PKCS8Open(der, cert)
	if err != nil {
		return nil, fromNative(err)
	}
	return &PrivateKey{handle: h}, nil
}

// VerifyHash verifies a detached signature over a digest.
func VerifyHash(digest, signature, cert []byte) error {
	return fromNative(native.VerifyHash(digest, signature, cert))
}

// VerifyData verifies a detached signature over raw data.
func VerifyData(data, signature, cert []byte) error {
	return fromNative(native.VerifyData(data, signature, cert))
}

// VerifyCertificate checks cert signature using issuerCert.
func VerifyCertificate(cert, issuerCert []byte) error {
	return fromNative(native.CertVerify(cert, issuerCert))
}

// CheckCertificateValidity checks notBefore/notAfter (unixSecs 0 = now).
func CheckCertificateValidity(cert []byte, unixSecs int64) error {
	return fromNative(native.CertCheckValidity(cert, unixSecs))
}

// CertificateSPKI returns SubjectPublicKeyInfo DER.
func CertificateSPKI(cert []byte) ([]byte, error) {
	out, err := native.CertSPKI(cert)
	return out, fromNative(err)
}

// VerifyCRL verifies CRL signature using issuerCert.
func VerifyCRL(crl, issuerCert []byte) error {
	return fromNative(native.CRLVerify(crl, issuerCert))
}

// IsCertificateRevoked returns true when cert is listed on crl.
func IsCertificateRevoked(crl, issuerCert, cert []byte) (bool, error) {
	revoked, err := native.CRLCheckCert(crl, issuerCert, cert)
	return revoked, fromNative(err)
}

// CertificateCount returns X.509 certificates stored in PKCS#12.
func (k *Keystore) CertificateCount() (int, error) {
	if k == nil || k.handle == nil {
		return 0, ErrInvalidParam
	}
	n, err := k.handle.CertificateCount()
	return n, fromNative(err)
}

// GetCertificate returns certificate DER at index from PKCS#12.
func (k *Keystore) GetCertificate(index int) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	out, err := k.handle.GetCertificate(index)
	return out, fromNative(err)
}
