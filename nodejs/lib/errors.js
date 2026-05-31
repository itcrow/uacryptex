'use strict';

const RET_OK = 0;
const RET_MEMORY = 1;
const RET_INVALID_PARAM = 2;
const RET_VERIFY_FAILED = 3;

class UacryptexError extends Error {
  constructor(message, code = 0) {
    super(message || `uacryptex error ${code}`);
    this.name = 'UacryptexError';
    this.code = code;
  }
}

class MemoryError extends UacryptexError {
  constructor(message, code = RET_MEMORY) {
    super(message || 'memory allocation failed', code);
    this.name = 'MemoryError';
  }
}

class InvalidParamError extends UacryptexError {
  constructor(message, code = RET_INVALID_PARAM) {
    super(message || 'invalid parameter', code);
    this.name = 'InvalidParamError';
  }
}

class VerifyFailedError extends UacryptexError {
  constructor(message, code = RET_VERIFY_FAILED) {
    super(message || 'verification failed', code);
    this.name = 'VerifyFailedError';
  }
}

function mapNativeError(code, message) {
  if (code === RET_OK) return null;
  if (code === RET_MEMORY) return new MemoryError(message, code);
  if (code === RET_INVALID_PARAM) return new InvalidParamError(message, code);
  if (code === RET_VERIFY_FAILED) return new VerifyFailedError(message, code);
  return new UacryptexError(message || `native error ${code}`, code);
}

module.exports = {
  RET_OK,
  RET_MEMORY,
  RET_INVALID_PARAM,
  RET_VERIFY_FAILED,
  UacryptexError,
  MemoryError,
  InvalidParamError,
  VerifyFailedError,
  mapNativeError,
};
