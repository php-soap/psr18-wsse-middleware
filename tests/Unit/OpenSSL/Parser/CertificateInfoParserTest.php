<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use OpenSSLAsymmetricKey;
use phpseclib4\Math\BigInteger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\CertificateInfo;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\CertificateInfoParser;

final class CertificateInfoParserTest extends TestCase
{
    public function test_it_builds_the_certificate_info_value_objects(): void
    {
        $certificate = $this->certificate(4242, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\nkeyUsage = digitalSignature\n");

        $info = (new CertificateInfoParser())->parse($certificate);

        static::assertStringContainsString('CertificateInfo Subject', $info->subject()->toString());
        static::assertSame('4242', $info->issuerSerial()->serialNumber->toString());
        static::assertStringContainsString('CertificateInfo Subject', $info->issuerSerial()->issuer->toString());
        static::assertTrue($info->validity()->permits(Timestamp::now()));
        static::assertNotSame('', $info->subjectKeyIdentifier()->toBase64());
        static::assertTrue($info->keyUsage()?->permitsSigning());

        $expected = base64_encode((string) openssl_x509_fingerprint($certificate->contents(), 'sha1', true));
        static::assertSame($expected, $info->thumbprintSha1()->toBase64());
    }

    /**
     * XML-DSig mandates RFC 2253 for ds:X509IssuerName, and RFC 2253 orders relative names most-specific
     * first with a comma between each. Repeated types are separate relative names: a plus sign would claim
     * one multi-valued relative name, which is a different distinguished name. The expected strings here are
     * what openssl itself prints for these certificates under -nameopt RFC2253.
     */
    #[DataProvider('rfc2253Names')]
    public function test_it_renders_a_distinguished_name_per_rfc_2253(string $fixture, string $expected): void
    {
        $certificate = Certificate::fromFile(FIXTURE_DIR.'/certificates/'.$fixture);

        $info = (new CertificateInfoParser())->parse($certificate);

        static::assertSame($expected, $info->subject()->toString());
        // These fixtures are self-signed, so the issuer must render identically, and the issuer is the one
        // that goes on the wire in a ds:X509IssuerSerial reference.
        static::assertSame($expected, $info->issuerSerial()->issuer->toString());
    }

    /** @return iterable<string, array{string, string}> */
    public static function rfc2253Names(): iterable
    {
        yield 'repeated organizational units stay separate relative names' => [
            'dn-repeated-ou.pem',
            'CN=Leaf,OU=Security,OU=Engineering,DC=ACMECorp,DC=com',
        ];

        yield 'a genuine multi-valued relative name keeps its plus sign' => [
            'dn-multivalued-rdn.pem',
            'DC=com,CN=Leaf+OU=Eng',
        ];

        yield 'a slash in a value needs no escaping under rfc 2253' => [
            'dn-slash-in-value.pem',
            'OU=C,OU=A/B',
        ];
    }

    public function test_it_reads_the_serial_from_the_unambiguous_hex_field(): void
    {
        // openssl reports serialNumber in decimal on some builds and hexadecimal on others, so an all-digit
        // value is ambiguous: read as decimal, a hex serial like 12345678 becomes 12345678 instead of
        // 305419896. SerialNumberHex states the base, so it is read from there.
        $certificate = Certificate::fromFile(FIXTURE_DIR.'/certificates/dn-repeated-ou.pem');
        $fields = openssl_x509_parse($certificate->contents());
        static::assertIsArray($fields);
        static::assertIsString($fields['serialNumberHex']);

        $info = (new CertificateInfoParser())->parse($certificate);

        $expected = (new BigInteger($fields['serialNumberHex'], 16))->toString();
        static::assertSame($expected, $info->issuerSerial()->serialNumber->toString());
    }

    public function test_it_leaves_absent_optional_extensions_unset(): void
    {
        $certificate = $this->certificate(7, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        $info = (new CertificateInfoParser())->parse($certificate);

        static::assertNull($info->keyUsage());
        $this->expectException(CryptoOperationFailed::class);
        $info->subjectKeyIdentifier();
    }

    public function test_certificate_info_can_be_built_straight_from_a_certificate(): void
    {
        $certificate = $this->certificate(99, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        $info = CertificateInfo::fromCertificate($certificate);

        static::assertStringContainsString('CertificateInfo Subject', $info->subject()->toString());
        static::assertSame('99', $info->issuerSerial()->serialNumber->toString());
    }

    public function test_it_throws_on_an_unparseable_certificate(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        (new CertificateInfoParser())->parse(new Certificate('not-a-certificate'));
    }

    private function certificate(int $serial, string $configContents): Certificate
    {
        $config = ['config' => $this->configFile($configContents)];

        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $csr = openssl_csr_new(['commonName' => 'CertificateInfo Subject'], $private, $config);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365, $config + ['x509_extensions' => 'v3'], $serial);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $pem));
        static::assertIsString($pem);

        return new Certificate($pem);
    }

    private function configFile(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'wsse-ossl-');
        static::assertIsString($path);
        file_put_contents($path, $contents);

        return $path;
    }
}
