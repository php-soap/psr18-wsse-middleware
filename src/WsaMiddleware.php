<?php

namespace Soap\Psr18WsseMiddleware;

use DOMDocument;
use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\RequestInterface;
use RobRichards\WsePhp\WSASoap;
use Soap\Psr18Transport\HttpBinding\SoapActionDetector;
use Soap\Psr18Transport\Xml\XmlMessageManipulator;
use VeeWee\Xml\Dom\Document;

class WsaMiddleware implements Plugin
{
    const WSA_ADDRESS_ANONYMOUS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous';

    private string $address;

    public function __construct(string $address = self::WSA_ADDRESS_ANONYMOUS)
    {
        $this->address = $address;
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        return $next(
            (new XmlMessageManipulator)(
                $request,
                function (Document $document) use ($request) : void {
                    $wsa = new WSASoap($document->toUnsafeDocument());
                    $wsa->addAction(SoapActionDetector::detectFromRequest($request));
                    $wsa->addTo((string) $request->getUri());
                    $wsa->addMessageID();
                    $wsa->addReplyTo($this->address);
                }
            )
        );
    }
}
