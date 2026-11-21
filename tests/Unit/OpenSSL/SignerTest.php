<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use LogicException;
use OpenSSLAsymmetricKey;
use phpseclib4\Crypt\DSA;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer;

final class SignerTest extends TestCase
{
    public function test_it_signs_and_verifies_with_every_rsa_method(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();
        $data = 'the canonicalized SignedInfo';

        foreach ([SignatureMethod::RSA_SHA1, SignatureMethod::RSA_SHA256, SignatureMethod::RSA_SHA384, SignatureMethod::RSA_SHA512] as $method) {
            $signature = $signer->sign($private, $data, $method);

            static::assertNotSame('', $signature);
            static::assertTrue($signer->verify($certificate, $data, $signature, $method));
        }
    }

    public function test_it_signs_and_verifies_with_every_ecdsa_method(): void
    {
        $signer = new Signer();
        $data = 'the canonicalized SignedInfo';

        foreach ([
            [SignatureMethod::ECDSA_SHA256, 'prime256v1', 64],
            [SignatureMethod::ECDSA_SHA384, 'secp384r1', 96],
            [SignatureMethod::ECDSA_SHA512, 'secp521r1', 132],
        ] as [$method, $curve, $width]) {
            [$private, $certificate] = $this->ecKeyAndCertificate($curve);
            $signature = $signer->sign($private, $data, $method);

            // The ECDSA SignatureValue is the fixed-width r||s pair XML Signature carries, two coordinates each
            // padded to the curve size, so the library emits it directly with no DER conversion.
            static::assertSame($width, strlen($signature));
            static::assertTrue($signer->verify($certificate, $data, $signature, $method));
        }
    }

    public function test_it_signs_and_verifies_with_dsa_sha1(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->dsaKeyAndCertificate();
        $data = 'the canonicalized SignedInfo';

        $signature = $signer->sign($private, $data, SignatureMethod::DSA_SHA1);

        // DSA-SHA1 carries r||s with each coordinate padded to the 160-bit subgroup, twenty bytes apiece.
        static::assertSame(40, strlen($signature));
        static::assertTrue($signer->verify($certificate, $data, $signature, SignatureMethod::DSA_SHA1));
    }

    public function test_verify_fails_for_tampered_data(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'original', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($certificate, 'tampered', $signature, SignatureMethod::RSA_SHA256));
    }

    public function test_verify_fails_for_a_tampered_ecdsa_signature(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->ecKeyAndCertificate('prime256v1');

        $signature = $signer->sign($private, 'payload', SignatureMethod::ECDSA_SHA256);

        static::assertFalse($signer->verify($certificate, 'payload', strrev($signature), SignatureMethod::ECDSA_SHA256));
    }

    public function test_verify_fails_for_a_different_key(): void
    {
        $signer = new Signer();
        [$private] = $this->keyAndCertificate();
        [, $otherCertificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'payload', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($otherCertificate, 'payload', $signature, SignatureMethod::RSA_SHA256));
    }

    public function test_verify_fails_when_the_methods_digest_differs(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'payload', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($certificate, 'payload', $signature, SignatureMethod::RSA_SHA512));
    }

    public function test_a_malformed_signature_is_rejected_and_never_treated_as_valid(): void
    {
        $signer = new Signer();
        [, $certificate] = $this->keyAndCertificate();

        // A garbage signature must come back as a strict false, never a truthy result (a -1->true
        // forgery trap), and without distinguishing "malformed" from "invalid".
        static::assertFalse($signer->verify($certificate, 'payload', 'not-a-real-signature', SignatureMethod::RSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', '', SignatureMethod::RSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', str_repeat('A', 5000), SignatureMethod::RSA_SHA256));
    }

    public function test_a_malformed_ecdsa_signature_is_rejected(): void
    {
        $signer = new Signer();
        [, $certificate] = $this->ecKeyAndCertificate('prime256v1');

        // An odd-length pair cannot split into r and s, and a wrong-width pair cannot match the curve; both are
        // a normal verification failure, never an error that leaks detail.
        static::assertFalse($signer->verify($certificate, 'payload', 'odd', SignatureMethod::ECDSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', '', SignatureMethod::ECDSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', str_repeat('A', 64), SignatureMethod::ECDSA_SHA256));
    }

    public function test_signing_fails_when_the_key_is_not_a_private_key(): void
    {
        $signer = new Signer();
        [, $certificate] = $this->keyAndCertificate();

        // A certificate PEM carries no private key, so loading it for signing fails. The key is our own
        // (a non-oracle path), so the failure surfaces as OpenSslException.
        $this->expectException(OpenSslException::class);
        $signer->sign(new Key($certificate->contents()), 'payload', SignatureMethod::RSA_SHA256);
    }

    public function test_verify_fails_when_the_certificate_is_not_readable(): void
    {
        $signer = new Signer();
        [$private] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'payload', SignatureMethod::RSA_SHA256);

        // An unreadable certificate is a setup error on a trusted input, so it surfaces rather than being
        // silently swallowed; the SignatureValidator translates it into a failed verification.
        $this->expectException(OpenSslException::class);
        $signer->verify(new Certificate('not a certificate'), 'payload', $signature, SignatureMethod::RSA_SHA256);
    }

    /**
     * Every asymmetric signature method the enum advertises must be executable by the signer: none may map to
     * an unsupported algorithm. This guards the enum against re-introducing a case the engine cannot apply.
     */
    public function test_every_asymmetric_signature_method_is_executable(): void
    {
        $signer = new Signer();

        foreach (SignatureMethod::cases() as $method) {
            if ($method->keyKind() === SignatureKeyKind::Hmac) {
                continue;
            }

            [$private] = $this->keyForMethod($method);
            $signature = $signer->sign($private, 'payload', $method);
            static::assertNotSame('', $signature);
        }
    }

    public function test_a_keyed_mac_method_is_not_the_signers_business(): void
    {
        [$private] = $this->keyAndCertificate();

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Hmac');

        (new Signer())->sign($private, 'payload', SignatureMethod::HMAC_SHA256);
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function keyForMethod(SignatureMethod $method): array
    {
        return match (true) {
            $method->keyKind() === SignatureKeyKind::Ecdsa => $this->ecKeyAndCertificate('prime256v1'),
            $method === SignatureMethod::DSA_SHA1 => $this->dsaKeyAndCertificate(),
            default => $this->keyAndCertificate(),
        };
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function ecKeyAndCertificate(string $curve): array
    {
        $private = openssl_pkey_new(['curve_name' => $curve, 'private_key_type' => OPENSSL_KEYTYPE_EC]);

        return $this->exportKeyAndCertificate($private);
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function dsaKeyAndCertificate(): array
    {
        // DSA keys generated through openssl_pkey_new cannot be self-signed into a certificate by every libssl
        // build, so the key pair is produced by the RSA/EC library and exported as PEM directly.
        $private = DSA::createKey(1024, 160);
        $privatePem = (string) $private;
        $publicPem = (string) $private->getPublicKey();

        return [new Key($privatePem), new Certificate($publicPem)];
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function keyAndCertificate(): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        return $this->exportKeyAndCertificate($private);
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function exportKeyAndCertificate(OpenSSLAsymmetricKey|false $private): array
    {
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
