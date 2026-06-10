/// Native status codes from `uacryptex-core`.
class RetCode {
  static const int ok = 0;
  static const int memory = 1;
  static const int invalidParam = 2;
  static const int verifyFailed = 3;
}

/// Base error with optional native status [code].
class UacryptexException implements Exception {
  UacryptexException(this.message, {this.code});

  final String message;
  final int? code;

  @override
  String toString() =>
      code == null ? 'UacryptexException: $message' : 'UacryptexException($code): $message';
}

class AllocationException extends UacryptexException {
  AllocationException(super.message, {super.code});
}

class InvalidParamException extends UacryptexException {
  InvalidParamException(super.message, {super.code});
}

class VerifyFailedException extends UacryptexException {
  VerifyFailedException(super.message, {super.code});
}

UacryptexException? mapNativeError(int code, String message) {
  if (code == RetCode.ok) return null;
  final msg = message.isEmpty ? 'native error $code' : message;
  switch (code) {
    case RetCode.memory:
      return AllocationException(msg, code: code);
    case RetCode.invalidParam:
      return InvalidParamException(msg, code: code);
    case RetCode.verifyFailed:
      return VerifyFailedException(msg, code: code);
    default:
      return UacryptexException(msg, code: code);
  }
}

void checkNative(int code, String message) {
  final error = mapNativeError(code, message);
  if (error != null) throw error;
}
