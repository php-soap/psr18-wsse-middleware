<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\WSSecurity\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\SignatureLocator;
use VeeWee\Xml\Dom\Document;

final class Signature implements WsseEntry
{
    private KeyInterface $privateKey;
    private KeyIdentifier $keyIdentifier;

    private SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA1;
    private DigestMethod $digestmethod = DigestMethod::SHA1;

    private bool $signAllHeaders = true;
    private array $signSpecificHeaders = [];
    private bool $signBody = true;
    private bool $insertBefore = true;

    public function __construct(
        KeyInterface  $privateKey,
        KeyIdentifier $keyIdentifier
    ) {
        $this->privateKey = $privateKey;
        $this->keyIdentifier = $keyIdentifier;
    }

    public function withSignatureMethod(SignatureMethod $signatureMethod): self
    {
        $new = clone $this;
        $new->signatureMethod = $signatureMethod;

        return $new;
    }

    public function withDigestMethod(DigestMethod $digestMethod): self
    {
        $new = clone $this;
        $new->digestmethod = $digestMethod;

        return $new;
    }

    public function withSignAllHeaders(bool $signAllHeaders): self
    {
        $new = clone $this;
        $new->signAllHeaders = $signAllHeaders;

        return $new;
    }

    /**
     * [
     *    WSSESoap::WSUNS => [
     *        'Timestamp' => true
     *    ],
     *    WSASoap::WSANS_2005 => [
     *        'To' => true
     *    ]
     * ];
     */
    public function withSignSpecificHeaders(array $signSpecificHeaders): self
    {
        $new = clone $this;
        $new->signAllHeaders = false;
        $new->signSpecificHeaders = $signSpecificHeaders;

        return $new;
    }

    public function withSignBody(bool $signBody): self
    {
        $new = clone $this;
        $new->signBody = $signBody;

        return $new;
    }

    public function withInsertBefore(bool $insertBefore): self
    {
        $new = clone $this;
        $new->insertBefore = $insertBefore;

        return $new;
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $securityKey = new XMLSecurityKey($this->signatureMethod->value, ['type' => 'private']);
        $securityKey->passphrase = $this->privateKey->passphrase();
        $securityKey->loadKey($this->privateKey->contents(), isFile: false, isCert: $this->privateKey->isCertificate());

        $wsse->signAllHeaders = $this->signAllHeaders;
        $wsse->signBody = $this->signBody;

        $wsse->signSoapDoc($securityKey, [
            'algorithm' => $this->digestmethod->value,
            'signSpecificHeaders' => $this->signSpecificHeaders,
            'insertBefore' => $this->insertBefore,
        ]);

        $signature = (new SignatureLocator())($envelope);
        ($this->keyIdentifier)($envelope, $wsse, $signature);
    }
}
