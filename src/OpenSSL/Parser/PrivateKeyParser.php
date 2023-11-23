<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

final class PrivateKeyParser
{
    public function __invoke(HiddenString $privateKey, ?HiddenString $password = null): Key
    {
        $parsed = '';
        $key = @openssl_pkey_get_private($privateKey->getString(), $password?->getString() ?: null);
        if (!$key) {
            throw InvalidKeyException::unableToReadPrivateKey();
        }

        $result = @openssl_pkey_export($key, $parsed, $password?->getString() ?: null);
        if (!$result) {
            throw InvalidKeyException::unableToReadPrivateKey();
        }

        return (new Key($parsed))->withPassphrase($password?->getString() ?? '');
    }
}
