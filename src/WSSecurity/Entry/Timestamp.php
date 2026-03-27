<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use DOMDocument;
use RobRichards\WsePhp\WSSESoap;

final class Timestamp implements WsseEntry
{
    private int $secondsToExpire;

    public function __construct(int $secondsToExpire = 3600)
    {
        $this->secondsToExpire = $secondsToExpire;
    }

    public function __invoke(DOMDocument $envelope, WSSESoap $wsse): void
    {
        $wsse->addTimestamp($this->secondsToExpire);
    }
}
