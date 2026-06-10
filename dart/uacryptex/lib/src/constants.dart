/// Content cipher for CMS enveloped data (`uacryptex_cms_envelop_encrypt_with_cipher`).
class ContentCipher {
  static const int gost28147Cfb = 0;
  static const int kalyna256Gcm = 1;
  static const int kalyna128Gcm = 2;
  static const int kalyna512Gcm = 3;
}

/// CRL types for `generateCrl`.
class CrlType {
  static const int delta = 0;
  static const int full = 1;
}

/// Cryptonite `GeneralName_PR` / `UACRYPTEX_GN_*`.
class GeneralNameKind {
  static const int otherName = 0;
  static const int rfc822Name = 1;
  static const int dnsName = 2;
  static const int x400Address = 3;
  static const int directoryName = 4;
  static const int ediPartyName = 5;
  static const int uri = 6;
  static const int ipAddress = 7;
  static const int registeredId = 8;
}

/// Cryptonite `KeyUsageBits` flags for X.509 keyUsage extension.
class KeyUsageBits {
  static const int digitalSignature = 0x00000001;
  static const int nonRepudiation = 0x00000002;
  static const int keyEncipherment = 0x00000004;
  static const int dataEncipherment = 0x00000008;
  static const int keyAgreement = 0x00000010;
  static const int keyCertSign = 0x00000020;
  static const int crlSign = 0x00000040;
  static const int encipherOnly = 0x00000080;
  static const int decipherOnly = 0x00000100;
}
