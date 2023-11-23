<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\X509PublicCertificateParser;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use function Psl\File\read;

final class X509PublicCertificateParserTest extends TestCase
{

    public function test_it_can_read_public_x509_key(): void
    {
        $parser = new X509PublicCertificateParser();
        $file = FIXTURE_DIR . '/certificates/wsse-server-x509.crt';

        $actual = $parser(new HiddenString(read($file)));

        static::assertInstanceOf(Certificate::class, $actual);
        static::assertStringEqualsFile($file, $actual->contents());
    }

    public function test_it_can_read_from_bundle(): void
    {
        $bundle = FIXTURE_DIR . '/certificates/wsse-client-x509.pem';
        $parser = new X509PublicCertificateParser();

        $actual = $parser(new HiddenString(read($bundle)));

        static::assertInstanceOf(Certificate::class, $actual);
        static::assertStringContainsString('CERTIFICATE', $actual->contents());
    }

    public function test_it_can_not_read_invalid_certificate(): void
    {
        $key = 'notavalidkey';
        $parser = new X509PublicCertificateParser();

        $this->expectException(InvalidKeyException::class);
        $parser(new HiddenString($key));
    }
}
