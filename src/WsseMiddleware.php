<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18Transport\Xml\XmlMessageManipulator;
use VeeWee\Xml\Dom\Document;

final class WsseMiddleware implements Plugin
{
    private string $privateKeyFile;
    private string $publicKeyFile;
    private string $serverCertificateFile = '';
    private int $timestamp = 3600;
    private bool $signAllHeaders = false;
    private string $digitalSignMethod = XMLSecurityKey::RSA_SHA1;
    private string $userTokenName = '';
    private string $userTokenPassword = '';
    private bool $userTokenDigest = false;
    private bool $encrypt = false;
    private bool $hasUserToken = false;
    private bool $serverCertificateHasSubjectKeyIdentifier = true;

    public function __construct(string $privateKeyFile, string $publicKeyFile)
    {
        $this->privateKeyFile = $privateKeyFile;
        $this->publicKeyFile = $publicKeyFile;
    }

    public function withTimestamp(int $timestamp = 3600): self
    {
        $new = clone $this;
        $new->timestamp = $timestamp;

        return $new;
    }

    public function withAllHeadersSigned(): self
    {
        $new = clone $this;
        $new->signAllHeaders = true;

        return $new;
    }

    public function withDigitalSignMethod(string $digitalSignMethod): self
    {
        $new = clone $this;
        $new->digitalSignMethod = $digitalSignMethod;

        return $new;
    }

    public function withUserToken(string $username, string $password = '', bool $digest = false): self
    {
        $new = clone $this;
        $new->hasUserToken = true;
        $new->userTokenName = $username;
        $new->userTokenPassword = $password;
        $new->userTokenDigest = $digest;

        return $new;
    }

    public function withEncryption(string $serverCertificateFile): self
    {
        $new = clone $this;
        $new->encrypt = true;
        $new->serverCertificateFile = $serverCertificateFile;

        return $new;
    }

    public function withServerCertificateHasSubjectKeyIdentifier(bool $hasSubjectKeyIdentifier): self
    {
        $new = clone $this;
        $new->serverCertificateHasSubjectKeyIdentifier = $hasSubjectKeyIdentifier;

        return $new;
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        return $this->beforeRequest($next, $request)->then(
            fn (ResponseInterface $response): ResponseInterface => $this->afterResponse($response)
        );
    }

    public function beforeRequest(callable $handler, RequestInterface $request): Promise
    {
        $request = (new XmlMessageManipulator())(
            $request,
            function (Document $xml) {
                $wsse = new WSSESoap($xml->toUnsafeDocument());

                // Prepare the WSSE soap class:
                $wsse->signAllHeaders = $this->signAllHeaders;
                $wsse->addTimestamp($this->timestamp);

                // Add a user token if this is configured.
                if ($this->hasUserToken) {
                    $wsse->addUserToken($this->userTokenName, $this->userTokenPassword, $this->userTokenDigest);
                }

                //  Add certificate (BinarySecurityToken) to the message
                $token = $wsse->addBinaryToken(file_get_contents($this->publicKeyFile));

                // Create new XMLSec Key using the dsigType and type is private key
                $key = new XMLSecurityKey($this->digitalSignMethod, ['type' => 'private']);
                $key->loadKey($this->privateKeyFile, true);
                $wsse->signSoapDoc($key);

                //  Attach token pointer to Signature:
                $wsse->attachTokentoSig($token);

                // Add end-to-end encryption if configured:
                if ($this->encrypt) {
                    $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
                    $key->generateSessionKey();
                    $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']);
                    $siteKey->loadKey($this->serverCertificateFile, true, true);
                    $wsse->encryptSoapDoc($siteKey, $key, [
                        'KeyInfo' => [
                            'X509SubjectKeyIdentifier' => $this->serverCertificateHasSubjectKeyIdentifier,
                        ]
                    ]);
                }
            }
        );

        return $handler($request);
    }

    public function afterResponse(ResponseInterface $response): ResponseInterface
    {
        if (!$this->encrypt) {
            return $response;
        }

        return (new XmlMessageManipulator())(
            $response,
            function (Document $xml) {
                $wsse = new WSSESoap($xml->toUnsafeDocument());
                $wsse->decryptSoapDoc(
                    $xml->toUnsafeDocument(),
                    [
                        'keys' => [
                            'private' => [
                                'key'    => $this->privateKeyFile,
                                'isFile' => true,
                                'isCert' => false,
                            ]
                        ]
                    ]
                );
            }
        );
    }
}
