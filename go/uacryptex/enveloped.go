package uacryptex

// EnvelopCMS encrypts data for recipientCert using originatorKey (DSTU4145 DH + GOST28147-CFB).
// Returns PKCS#7 ContentInfo DER wrapping EnvelopedData.
func EnvelopCMS(data []byte, originatorKey *PrivateKey, recipientCert []byte) ([]byte, error) {
	if originatorKey == nil || originatorKey.handle == nil {
		return nil, ErrInvalidParam
	}
	if len(recipientCert) == 0 {
		return nil, ErrInvalidParam
	}
	cms, err := originatorKey.handle.CMSEnvelopEncrypt(data, recipientCert)
	return cms, fromNative(err)
}

// DecryptCMS decrypts PKCS#7 EnvelopedData using recipientKey and recipientCert.
//
// Pass nil originatorCert when the originator certificate is embedded in the CMS.
// Pass nil external when ciphertext is embedded in the structure.
func DecryptCMS(cms []byte, recipientKey *PrivateKey, recipientCert []byte, originatorCert, external []byte) ([]byte, error) {
	if recipientKey == nil || recipientKey.handle == nil {
		return nil, ErrInvalidParam
	}
	if len(recipientCert) == 0 || len(cms) == 0 {
		return nil, ErrInvalidParam
	}
	plain, err := recipientKey.handle.CMSEnvelopDecrypt(cms, external, originatorCert, recipientCert)
	return plain, fromNative(err)
}
