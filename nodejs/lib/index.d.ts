export const VERSION = '0.1.0';

export class UacryptexError extends Error {
  code: number;
  constructor(message?: string, code = 0) {
    super(message || `uacryptex error ${code}`);
    this.name = 'UacryptexError';
    this.code = code;
  }
}

export class MemoryError extends UacryptexError {}
export class InvalidParamError extends UacryptexError {}
export class VerifyFailedError extends UacryptexError {}

export class PrivateKey {
  close(): void;
  signHash(digest: Buffer): Buffer;
}

export class Keystore {
  close(): void;
  setCertificate(cert: Buffer): void;
  privateKey(): PrivateKey;
}

export function libraryVersion(): string;
export function openPrivateKey(key: Buffer, cert: Buffer): PrivateKey;
export function openPkcs12(data: Buffer, password: string): Keystore;
export function signCms(data: Buffer, key: PrivateKey): Buffer;
export function verifyCms(data: Buffer, cms: Buffer): void;
export function envelopCms(data: Buffer, originatorKey: PrivateKey, recipientCert: Buffer): Buffer;
export function decryptCms(
  cms: Buffer,
  recipientKey: PrivateKey,
  recipientCert: Buffer,
  originatorCert?: Buffer | null,
  external?: Buffer | null
): Buffer;
