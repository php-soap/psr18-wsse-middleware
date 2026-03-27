<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\RequestInterface;
use RobRichards\WsePhp\WSASoap;
use Soap\Psr18Transport\HttpBinding\SoapActionDetector;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Legacy\LegacyInterop;

final class WsaMiddleware2005 implements Plugin
{
    const WSA_ADDRESS2005_ANONYMOUS = 'http://www.w3.org/2005/08/addressing/anonymous';

    private string $address;

    public function __construct(string $address = self::WSA_ADDRESS2005_ANONYMOUS)
    {
        $this->address = $address;
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        $legacyDoc = LegacyInterop::parseBody((string) $request->getBody());

        $wsa = new WSASoap($legacyDoc, WSASoap::WSANS_2005);
        $wsa->addAction(SoapActionDetector::detectFromRequest($request));
        $wsa->addTo((string) $request->getUri());
        $wsa->addMessageID();
        $wsa->addReplyTo($this->address);

        return $next($request->withBody(LegacyInterop::toStream($legacyDoc)));
    }
}
