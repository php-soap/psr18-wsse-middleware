<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use VeeWee\Xml\Dom\Document;

interface WsseEntry
{
    public function __invoke(Document $envelope, WSSESoap $wsse): void;
}
