<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Hash\Algorithm;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use function Psl\Hash\equals;

/**
 * Digest calculation and constant-time comparison. Comparisons of digests, tags and MACs MUST go through
 * equals() so a byte-by-byte timing side channel cannot leak how much of a value matched.
 */
final class Digest
{
    /**
     * Raw (binary) digest bytes for the given method. Raw, not hex, because XML-DSig DigestValue is the
     * base64 of the raw bytes.
     */
    public function hash(string $data, DigestMethod $method): string
    {
        // Psl\Hash\Algorithm is the typed source of the algorithm identity; native hash(binary: true) does
        // the raw-bytes finalization (Psl\Hash\hash only returns hex, but XML-DSig DigestValue needs raw).
        /** @psalm-suppress WeakHash - SHA-1 and RIPEMD-160 stay supported because XML-DSig peers still sign with them. */
        return hash($this->algorithm($method)->value, $data, binary: true);
    }

    /**
     * Timing-safe comparison. Returns false for unequal length without leaking where the difference is.
     */
    public function equals(string $known, string $given): bool
    {
        return equals($known, $given);
    }

    private function algorithm(DigestMethod $method): Algorithm
    {
        return match ($method) {
            DigestMethod::SHA1 => Algorithm::Sha1,
            DigestMethod::SHA256 => Algorithm::Sha256,
            DigestMethod::SHA384 => Algorithm::Sha384,
            DigestMethod::SHA512 => Algorithm::Sha512,
            DigestMethod::RIPEMD160 => Algorithm::Ripemd160,
        };
    }
}
