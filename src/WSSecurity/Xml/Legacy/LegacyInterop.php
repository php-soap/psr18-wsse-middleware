<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Legacy;

use DOMDocument;
use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * TODO: Remove this class and move back to veewee/xml once robrichards/wse-php migrates to the new DOM API.
 */
final class LegacyInterop
{
    public static function parseBody(string $xml): DOMDocument
    {
        $doc = new DOMDocument();
        self::disallowFalse($doc->loadXML($xml), 'Could not load SOAP envelope.');

        return $doc;
    }

    public static function toStream(DOMDocument $doc): StreamInterface
    {
        return Psr17FactoryDiscovery::findStreamFactory()->createStream(
            self::disallowFalse($doc->saveXML(), 'Could not serialize SOAP envelope.')
        );
    }

    /**
     * @template T
     * @param T|false $value
     * @return T
     */
    public static function disallowFalse(mixed $value, string $message): mixed
    {
        if ($value === false) {
            throw new RuntimeException($message);
        }

        return $value;
    }
}
