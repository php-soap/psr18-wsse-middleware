<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\PrivateKeyParser;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use function Psl\File\read;

final class PrivateKeyParserTest extends TestCase
{

    public function test_it_can_read_private_key(): void
    {
        $key = $this->createPrivateKey();
        $parser = new PrivateKeyParser();

        $actual = $parser(new HiddenString($key));

        static::assertInstanceOf(Key::class, $actual);
        static::assertSame($key, $actual->contents());
    }

    public function test_it_can_read_encrypted_private_key(): void
    {
        $key = $this->createPrivateKey($passPhrase = 'password');
        $parser = new PrivateKeyParser();

        static::assertStringContainsString('ENCRYPTED PRIVATE KEY', $key);

        $actual = $parser(new HiddenString($key), new HiddenString($passPhrase));

        static::assertInstanceOf(Key::class, $actual);
        static::assertSame($passPhrase, $actual->passphrase());
        static::assertStringContainsString('ENCRYPTED PRIVATE KEY', $actual->contents());
    }

    public function test_it_can_read_from_bundle(): void
    {
        $bundle = FIXTURE_DIR . '/certificates/wsse-client-x509.pem';
        $parser = new PrivateKeyParser();

        $actual = $parser(new HiddenString(read($bundle)));

        static::assertInstanceOf(Key::class, $actual);
        static::assertSame('', $actual->passphrase());
        static::assertStringContainsString('PRIVATE KEY', $actual->contents());
    }

    public function test_it_can_not_read_invalid_private_key(): void
    {
        $key = 'notavalidkey';
        $parser = new PrivateKeyParser();

        $this->expectException(InvalidKeyException::class);
        $parser(new HiddenString($key));
    }

    private function createPrivateKey(?string $passPhrase = null): string
    {
        $key = openssl_pkey_new();
        static::assertNotFalse($key);

        $parsed = '';
        $result = openssl_pkey_export($key, $parsed, $passPhrase);
        static::assertNotFalse($result);

        return $parsed;
    }
}
