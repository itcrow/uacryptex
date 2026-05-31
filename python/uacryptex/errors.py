"""Error types for uacryptex Python bindings."""

from __future__ import annotations

RET_OK = 0
RET_MEMORY = 1
RET_INVALID_PARAM = 2
RET_VERIFY_FAILED = 3


class UacryptexError(Exception):
    """Base error with optional native status code."""

    def __init__(self, message: str = "", code: int | None = None):
        super().__init__(message)
        self.code = code


class AllocationError(UacryptexError):
    """Native allocation failed (RET_MEMORY)."""


class InvalidParamError(UacryptexError):
    """Invalid argument (RET_INVALID_PARAM)."""


class VerifyFailedError(UacryptexError):
    """Signature or CMS verification failed (RET_VERIFY_FAILED)."""


def map_native_error(code: int, message: str) -> UacryptexError | None:
    if code == RET_OK:
        return None
    if code == RET_MEMORY:
        return AllocationError(message or "memory allocation failed", code)
    if code == RET_INVALID_PARAM:
        return InvalidParamError(message or "invalid parameter", code)
    if code == RET_VERIFY_FAILED:
        return VerifyFailedError(message or "verification failed", code)
    return UacryptexError(message or f"native error {code}", code)
