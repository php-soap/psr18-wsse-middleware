<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use VeeWee\Xml\Dom\Document;

final class Username implements WsseEntry
{
    private string $userName;
    private ?string $password = null;
    private bool $digest = false;

    public function __construct(string $userName)
    {
        $this->userName = $userName;
    }

    public function withPassword(string $password): self
    {
        $new = clone $this;
        $new->password = $password;

        return $new;
    }

    public function withDigest(bool $digest): self
    {
        $new = clone $this;
        $new->digest = $digest;

        return $new;
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $wsse->addUserToken(
            $this->userName,
            $this->password,
            $this->digest
        );
    }
}
