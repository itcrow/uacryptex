<?php

declare(strict_types=1);

namespace Itcrow\Uacryptex;

final class UacryptexError extends \RuntimeException
{
    public function __construct(
        string $message = '',
        public readonly int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message !== '' ? $message : "uacryptex error {$code}", $code, $previous);
    }
}

final class MemoryError extends UacryptexError
{
}

final class InvalidParamError extends UacryptexError
{
}

final class VerifyFailedError extends UacryptexError
{
}
