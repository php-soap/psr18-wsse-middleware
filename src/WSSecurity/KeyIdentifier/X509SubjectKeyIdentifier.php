<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use VeeWee\Xml\Dom\Document;
use function Psl\Type\string;

final class X509SubjectKeyIdentifier implements KeyIdentifier
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function __construct(private Certificate $certificate)
    {
    }

    public function __invoke(Document $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        $x509 = openssl_x509_parse($this->certificate->contents());
        if (!$x509) {
            return;
        }

        $keyId = string()->coerce($x509['extensions']['subjectKeyIdentifier'] ?? '');
        $exploded = explode(':', $keyId);
        $data = '';
        foreach ($exploded as $hexchar) {
            $data .= chr(hexdec($hexchar));
        }
        $encoded = base64_encode($data);

        (new CustomKeyIdentifier($encoded, self::VALUE_TYPE))
            ->withAttributes([
                'EncodingType' => self::ENCODING_TYPE,
            ])($envelope, $wsse, $parent);
    }
}
