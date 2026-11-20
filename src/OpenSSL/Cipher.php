<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use phpseclib4\Crypt\AES;
use phpseclib4\Crypt\Common\BlockCipher;
use phpseclib4\Crypt\TripleDES;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Throwable;

/**
 * Symmetric bulk encryption (AES-CBC/GCM, 3DES-CBC) routed through the symmetric cipher library.
 *
 * GCM authenticates its own ciphertext; CBC does not, and nothing in this library ties a CBC part to a
 * verified signature: Decrypt and VerifySignature are independent inbound blocks with no ordering or
 * coverage coupling between them. CBC is therefore refused inbound by default, and a deployment whose peer
 * only sends it names it in the accepted data encryption methods deliberately.
 *
 * The uniform decrypt failure does not close the padding oracle, and must not be read as doing so. It hides
 * which step failed; an oracle only needs whether the message was accepted, and a caller who can trigger
 * requests observes that from the difference between a returned response and a thrown one. Recovering a CBC
 * plaintext byte by byte therefore stays possible for a peer that can replay a captured EncryptedKey beside
 * a mangled CipherValue. Only narrowing the allow-list to GCM, or coupling a CBC part to a region a verified
 * signature covered, removes it.
 */
final class Cipher
{
    public function __construct(
        private readonly Random $random = new Random(),
    ) {
    }

    public function encrypt(
        #[SensitiveParameter] string $plaintext,
        SessionKey $key,
        DataEncryptionMethod $method,
    ): CipherText {
        $iv = $this->random->bytes($method->ivLength());

        try {
            $cipher = $this->cipher($method, $key->bytes(), $iv);

            if ($method->isGcm()) {
                $bytes = $cipher->encrypt($plaintext);

                return new CipherText($iv, $bytes, $cipher->getTag());
            }

            // For CBC the IV length equals the block size.
            $bytes = $cipher->encrypt($this->pad($plaintext, strlen($iv)));
        } catch (Throwable) {
            throw CryptoOperationFailed::encryptionFailed();
        }

        return new CipherText($iv, $bytes, null);
    }

    public function decrypt(
        CipherText $cipherText,
        SessionKey $key,
        DataEncryptionMethod $method,
    ): string {
        $ivLength = $method->ivLength();

        if ($method->isGcm()) {
            if ($cipherText->tag === null || strlen($cipherText->tag) !== $method->tagLength()) {
                // Reject a truncated/missing tag before decrypt (tag-forgery defense).
                throw CryptoOperationFailed::invalidAuthenticationTag();
            }
            if (strlen($cipherText->iv) !== $ivLength) {
                // A non-96-bit GCM IV weakens GHASH, so we refuse it outright.
                throw CryptoOperationFailed::decryptionFailed();
            }

            $tag = $cipherText->tag;

            try {
                $cipher = $this->cipher($method, $key->bytes(), $cipherText->iv);
                $cipher->setTag($tag);
                $plaintext = $cipher->decrypt($cipherText->bytes);
            } catch (Throwable) {
                throw CryptoOperationFailed::decryptionFailed();
            }

            return $plaintext;
        }

        if (strlen($cipherText->iv) !== $ivLength) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        try {
            $cipher = $this->cipher($method, $key->bytes(), $cipherText->iv);
            $padded = $cipher->decrypt($cipherText->bytes);
        } catch (Throwable) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        // For CBC the IV length equals the block size.
        return $this->unpad($padded, $ivLength);
    }

    /**
     * ISO 10126 / XML-Enc padding: random filler then a final octet holding the pad length (always 1..block).
     */
    private function pad(string $data, int $blockSize): string
    {
        $padLength = $blockSize - (strlen($data) % $blockSize);
        $filler = $padLength > 1 ? $this->random->bytes($padLength - 1) : '';

        return $data.$filler.chr($padLength);
    }

    private function unpad(string $data, int $blockSize): string
    {
        $length = strlen($data);
        if ($length === 0) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        $padLength = ord($data[$length - 1]);
        // Validate the pad length is plausible rather than trusting the final byte blindly.
        if ($padLength < 1 || $padLength > $blockSize || $padLength > $length) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        return substr($data, 0, $length - $padLength);
    }

    /**
     * Build a fresh cipher object per call, configured for the method. The key length is pinned before the key
     * is set so a wrong-length session key is rejected rather than silently re-sizing the cipher. We apply
     * ISO 10126 padding ourselves, so the library padding is disabled to keep the wire format intact.
     */
    private function cipher(
        DataEncryptionMethod $method,
        #[SensitiveParameter] string $key,
        string $iv,
    ): BlockCipher {
        if ($method === DataEncryptionMethod::TRIPLEDES_CBC) {
            $cipher = new TripleDES('cbc');
            // Pinned before the key is set: the cipher library otherwise expands a two-key session key into
            // K1||K2||K1, running 3DES at roughly 80-bit strength under a URI that promises three keys.
            $cipher->setKeyLength(192);
            $cipher->setKey($key);
            $cipher->setIV($iv);
            $cipher->disablePadding();

            return $cipher;
        }

        if ($method->isGcm()) {
            $cipher = new AES('gcm');
            $cipher->setKeyLength($this->aesKeyLength($method));
            $cipher->setKey($key);
            $cipher->setNonce($iv);

            return $cipher;
        }

        $cipher = new AES('cbc');
        $cipher->setKeyLength($this->aesKeyLength($method));
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->disablePadding();

        return $cipher;
    }

    /**
     * @return 128|192|256
     */
    private function aesKeyLength(DataEncryptionMethod $method): int
    {
        return match ($method) {
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES128_GCM => 128,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES192_GCM => 192,
            DataEncryptionMethod::AES256_CBC,
            DataEncryptionMethod::AES256_GCM => 256,
            DataEncryptionMethod::TRIPLEDES_CBC => throw CryptoOperationFailed::encryptionFailed(),
        };
    }
}
