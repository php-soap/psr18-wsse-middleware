<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry\WsseEntry;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Legacy\LegacyInterop;

final class WsseMiddleware implements Plugin
{
    /**
     * @var list<WsseEntry>
     */
    private array $outgoingEntries;
    /**
     * @var list<WsseEntry>
     */
    private array $incomingEntries;
    private bool $mustUnderstand = true;
    private ?string $actor = null;

    /**
     * @no-named-arguments
     * @param list<WsseEntry> $outgoing
     * @param list<WsseEntry> $incoming
     */
    public function __construct(
        array $outgoing = [],
        array $incoming = []
    ) {
        $this->outgoingEntries = $outgoing;
        $this->incomingEntries = $incoming;
    }

    public function withMustUnderstand(bool $mustUnderstand): self
    {
        $new = clone $this;
        $new->mustUnderstand = $mustUnderstand;

        return $new;
    }

    public function withActor(string $actor): self
    {
        $new = clone $this;
        $new->actor = $actor;

        return $new;
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        return $this->beforeRequest($next, $request)->then(
            fn (ResponseInterface $response): ResponseInterface => $this->afterResponse($response)
        );
    }

    /**
     * @param callable(RequestInterface): Promise $handler
     */
    public function beforeRequest(callable $handler, RequestInterface $request): Promise
    {
        if ($this->outgoingEntries) {
            $request = $this->applyWsseEntries($request, $this->outgoingEntries);
        }

        return $handler($request);
    }

    public function afterResponse(ResponseInterface $response): ResponseInterface
    {
        if (!$this->incomingEntries) {
            return $response;
        }

        return $this->applyWsseEntries($response, $this->incomingEntries);
    }

    /**
     * @template T of MessageInterface
     * @param T $message
     * @param list<WsseEntry> $entries
     * @return T
     */
    private function applyWsseEntries(MessageInterface $message, array $entries): MessageInterface
    {
        $legacyDoc = LegacyInterop::parseBody((string) $message->getBody());
        $wsse = new WSSESoap($legacyDoc, $this->mustUnderstand, $this->actor);

        foreach ($entries as $entry) {
            $entry($legacyDoc, $wsse);
        }

        return $message->withBody(LegacyInterop::toStream($legacyDoc));
    }
}
