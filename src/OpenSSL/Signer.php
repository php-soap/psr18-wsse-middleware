<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use LogicException;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Math\BigInteger;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Throwable;

/**
 * Asymmetric signing and verification (RSA / DSA / ECDSA) over the RSA/EC library. Each method selects a key
 * type and a hash; the library emits and accepts the same wire encoding XML Signature carries, so no signature
 * is reshaped here.
 *
 * ECDSA and DSA carry the SignatureValue as a fixed-width r||s pair. The library produces that directly for EC
 * (its IEEE format), and for DSA the two coordinates are padded to the subgroup width, so neither needs a DER
 * conversion around the crypto boundary.
 *
 * The HMAC methods are keyed by a secret rather than by a key pair and belong to the Hmac class beside this one.
 */
final class Signer
{
    // DSA-SHA1 uses a 160-bit subgroup, so each of r and s is twenty bytes in the XML Signature pair.
    private const DSA_COORDINATE_BYTES = 20;

    public function sign(
        #[SensitiveParameter] Key $privateKey,
        string $data,
        SignatureMethod $method,
    ): string {
        $key = $this->configure($this->loadPrivateKey($privateKey, $method), $method);

        // A failure throws OpenSslException with the real reason (a non-oracle path: the private key is ours,
        // not attacker input).
        try {
            /** @var string|array{r: BigInteger, s: BigInteger} $signature */
            $signature = $key->sign($data);
        } catch (Throwable $reason) {
            throw OpenSslException::operationFailed('sign the data', $reason->getMessage());
        }

        // RSA and EC return the wire bytes; DSA returns the raw r and s integers, padded to the subgroup width.
        if (is_string($signature)) {
            return $signature;
        }

        return $this->dsaToFixedWidth($signature);
    }

    public function verify(
        Certificate $publicCertificate,
        string $data,
        string $signature,
        SignatureMethod $method,
    ): bool {
        $key = $this->configure($this->loadPublicKey($publicCertificate, $method), $method);

        // The DSA pair is the fixed-width r||s value; a malformed pair is a normal verification failure, never
        // an error that leaks detail, so it maps to false rather than surfacing.
        $verifiable = $method === SignatureMethod::DSA_SHA1
            ? $this->dsaFromFixedWidth($signature)
            : $signature;
        if ($verifiable === null) {
            return false;
        }

        // The library returns a bool: a wrong or malformed signature is false (no oracle on attacker-controlled
        // signature bytes); a genuine setup error surfaces from key loading, not from here.
        try {
            return $key->verify($data, $verifiable) === true;
        } catch (Throwable) {
            return false;
        }
    }

    private function loadPrivateKey(#[SensitiveParameter] Key $key, SignatureMethod $method): PrivateKey
    {
        try {
            $loaded = PublicKeyLoader::loadPrivateKey($key->contents(), $key->passphrase());
        } catch (Throwable $reason) {
            throw OpenSslException::operationFailed('read the private key', $reason->getMessage());
        }

        if (!$this->matchesType($loaded, $method)) {
            throw OpenSslException::operationFailed('read the private key', 'the key is not an '.$this->keyName($method).' private key');
        }

        return $loaded;
    }

    private function loadPublicKey(Certificate $certificate, SignatureMethod $method): PublicKey
    {
        try {
            $loaded = PublicKeyLoader::loadPublicKey($certificate->contents());
        } catch (Throwable $reason) {
            throw OpenSslException::operationFailed('read the public key', $reason->getMessage());
        }

        if (!$this->matchesType($loaded, $method)) {
            throw OpenSslException::operationFailed('read the public key', 'the certificate is not an '.$this->keyName($method).' certificate');
        }

        return $loaded;
    }

    /**
     * @template T of PrivateKey|PublicKey
     *
     * @param T $key
     *
     * @return T
     */
    private function configure(PrivateKey|PublicKey $key, SignatureMethod $method): PrivateKey|PublicKey
    {
        $hash = $this->hash($method);

        if ($key instanceof RSA) {
            /** @var RSA $hashed */
            $hashed = $key->withHash($hash);
            /** @var T $configured */
            $configured = $hashed->withPadding(RSA::SIGNATURE_PKCS1);

            return $configured;
        }

        if ($key instanceof EC) {
            // IEEE P1363 is the fixed-width r||s pair the XML Signature SignatureValue carries.
            /** @var EC $hashed */
            $hashed = $key->withHash($hash);
            /** @var T $configured */
            $configured = $hashed->withSignatureFormat('IEEE');

            return $configured;
        }

        if ($key instanceof DSA) {
            // The raw format yields the r and s integers, padded to the subgroup width afterwards.
            /** @var DSA $hashed */
            $hashed = $key->withHash($hash);
            /** @var T $configured */
            $configured = $hashed->withSignatureFormat('Raw');

            return $configured;
        }

        // matchesType has already proven the key is one of the three concrete types this method handles.
        throw OpenSslException::operationFailed('configure the key', 'the key type is not supported');
    }

    private function matchesType(PrivateKey|PublicKey $key, SignatureMethod $method): bool
    {
        return match ($method->keyKind()) {
            SignatureKeyKind::Ecdsa => $key instanceof EC,
            SignatureKeyKind::Dsa => $key instanceof DSA,
            SignatureKeyKind::Rsa => $key instanceof RSA,
            SignatureKeyKind::Hmac => throw self::notAsymmetric($method),
        };
    }

    private function hash(SignatureMethod $method): string
    {
        return match ($method) {
            SignatureMethod::RSA_SHA1, SignatureMethod::DSA_SHA1 => 'sha1',
            SignatureMethod::RSA_SHA256, SignatureMethod::ECDSA_SHA256 => 'sha256',
            SignatureMethod::RSA_SHA384, SignatureMethod::ECDSA_SHA384 => 'sha384',
            SignatureMethod::RSA_SHA512, SignatureMethod::ECDSA_SHA512 => 'sha512',
            SignatureMethod::HMAC_SHA1,
            SignatureMethod::HMAC_SHA224,
            SignatureMethod::HMAC_SHA256,
            SignatureMethod::HMAC_SHA384,
            SignatureMethod::HMAC_SHA512 => throw self::notAsymmetric($method),
        };
    }

    private function keyName(SignatureMethod $method): string
    {
        return match ($method->keyKind()) {
            SignatureKeyKind::Ecdsa => 'EC',
            SignatureKeyKind::Dsa => 'DSA',
            SignatureKeyKind::Rsa => 'RSA',
            SignatureKeyKind::Hmac => throw self::notAsymmetric($method),
        };
    }

    private static function notAsymmetric(SignatureMethod $method): LogicException
    {
        return new LogicException(sprintf(
            '%s is keyed by a shared secret and is computed by the Hmac class, not by the Signer.',
            $method->name,
        ));
    }

    /**
     * @param array{r: BigInteger, s: BigInteger} $signature
     */
    private function dsaToFixedWidth(array $signature): string
    {
        return $this->pad($signature['r']->toBytes()).$this->pad($signature['s']->toBytes());
    }

    /**
     * @return array{r: BigInteger, s: BigInteger}|null null when the pair is not a valid fixed-width r||s value
     */
    private function dsaFromFixedWidth(string $signature): ?array
    {
        if (strlen($signature) !== 2 * self::DSA_COORDINATE_BYTES) {
            return null;
        }

        return [
            'r' => new BigInteger(substr($signature, 0, self::DSA_COORDINATE_BYTES), 256),
            's' => new BigInteger(substr($signature, self::DSA_COORDINATE_BYTES), 256),
        ];
    }

    private function pad(string $coordinate): string
    {
        return str_pad($coordinate, self::DSA_COORDINATE_BYTES, "\x00", STR_PAD_LEFT);
    }
}
