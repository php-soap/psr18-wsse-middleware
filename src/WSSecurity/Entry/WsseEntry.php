<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use DOMDocument;
use RobRichards\WsePhp\WSSESoap;

interface WsseEntry
{
    public function __invoke(DOMDocument $envelope, WSSESoap $wsse): void;
}
