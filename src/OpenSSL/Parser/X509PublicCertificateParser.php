<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

final class X509PublicCertificateParser
{
    public function __invoke(HiddenString $publicKey): Certificate
    {
        $parsed = '';
        $key = @openssl_x509_read($publicKey->getString());
        if (!$key) {
            throw InvalidKeyException::unableToReadPublicKey();
        }

        $result = @openssl_x509_export($key, $parsed);
        if (!$result) {
            throw InvalidKeyException::unableToReadPublicKey();
        }

        return new Certificate($parsed);
    }
}
