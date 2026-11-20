<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use phpseclib4\Math\BigInteger;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SerialNumber;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use function Psl\Type\non_empty_string;

/**
 * Normalises the serial number openssl reports into a SerialNumber: openssl gives it in decimal on some builds
 * and hexadecimal on others, and serials routinely exceed the platform integer range, so the conversion keeps
 * arbitrary precision. The arbitrary-precision math is why this lives at the openssl/crypto boundary.
 */
final class SerialNumberParser
{
    /**
     * @throws CryptoOperationFailed when the serial number is neither decimal nor hexadecimal
     */
    public function parse(string $serialNumber): SerialNumber
    {
        if (preg_match('/^\d+$/', $serialNumber) === 1) {
            return SerialNumber::fromDecimal($serialNumber);
        }

        return $this->parseHex($serialNumber);
    }

    /**
     * Converts a hexadecimal serial, with or without the 0x prefix, keeping arbitrary precision.
     *
     * @throws CryptoOperationFailed when the value is not hexadecimal
     */
    public function parseHex(string $serialNumber): SerialNumber
    {
        $hex = str_starts_with($serialNumber, '0x') ? substr($serialNumber, 2) : $serialNumber;
        if ($hex === '' || preg_match('/^[0-9A-Fa-f]+$/', $hex) !== 1) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return SerialNumber::fromDecimal(non_empty_string()->coerce((new BigInteger($hex, 16))->toString()));
    }
}
