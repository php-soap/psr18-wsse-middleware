<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PrivateKey;
use phpseclib4\Crypt\RSA\PublicKey;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Throwable;

/**
 * RSA key transport: wrap/unwrap a symmetric session key under a recipient's RSA key. OAEP (the secure
 * default, with either SHA-1 or SHA-256) and the opt-in legacy RSA-1_5 are supported. Unwrap collapses every
 * failure to one uniform error so it cannot become a padding oracle.
 *
 * Both paddings run through the same vetted RSA implementation so the OAEP digest is not pinned to a single
 * hash and no padding is hand-rolled.
 */
final class KeyTransport
{
    public function wrap(
        SessionKey $sessionKey,
        Certificate $recipientCertificate,
        KeyTransportAlgorithm $algorithm,
    ): string {
        $publicKey = PublicKeyLoader::load($recipientCertificate->contents());
        if (!$publicKey instanceof PublicKey) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        $configured = $this->configure($publicKey, $algorithm);
        if (!$configured instanceof PublicKey) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        // A failure here is a non-oracle path (our recipient key / data), so the real reason may surface.
        return $configured->encrypt($sessionKey->bytes());
    }

    public function unwrap(
        #[SensitiveParameter] string $wrappedKey,
        #[SensitiveParameter] Key $privateKey,
        KeyTransportAlgorithm $algorithm,
    ): SessionKey {
        try {
            $key = PublicKeyLoader::load($privateKey->contents(), $privateKey->passphrase());

            $configured = $key instanceof PrivateKey ? $this->configure($key, $algorithm) : null;
            if (!$configured instanceof PrivateKey) {
                throw CryptoOperationFailed::decryptionFailed();
            }

            return SessionKey::fromBytes($configured->decrypt($wrappedKey));
        } catch (Throwable) {
            // Uniform: never reveal whether RSA padding was valid (Bleichenbacher / Marvin).
            throw CryptoOperationFailed::decryptionFailed();
        }
    }

    private function configure(RSA $key, KeyTransportAlgorithm $algorithm): RSA
    {
        $labelHash = $algorithm->labelHash;
        $mgfHash = $algorithm->mgfHash;
        if (!$algorithm->isOaep() || $labelHash === null || $mgfHash === null) {
            /** @var RSA $configured */
            $configured = $key->withPadding(RSA::ENCRYPTION_PKCS1);

            return $configured;
        }

        /** @var RSA $configured */
        $configured = $key->withPadding(RSA::ENCRYPTION_OAEP);
        /** @var RSA $configured */
        $configured = $configured->withHash($labelHash->value);
        /** @var RSA $configured */
        $configured = $configured->withMGFHash($mgfHash->value);

        return $configured;
    }
}
