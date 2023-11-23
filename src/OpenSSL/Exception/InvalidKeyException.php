<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Exception;

use RuntimeException;

final class InvalidKeyException extends RuntimeException
{
    public static function unableToReadPrivateKey(): self
    {
        return new self('Unable to read the format of the provided private key.');
    }

    public static function unableToReadPublicKey(): self
    {
        return new self('Unable to read the format of the provided public key.');
    }
}
