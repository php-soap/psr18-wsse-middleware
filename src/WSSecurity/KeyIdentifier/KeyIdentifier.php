<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use VeeWee\Xml\Dom\Document;

/**
 * @link https://www.ibm.com/docs/en/was/8.5.5?topic=services-key-information
 * This interface provides a flexible way to add key identifiers to signatures or an encryption key.
 */
interface KeyIdentifier
{
    /**
     * The parent can either be the ds:Signature or xenc:EncryptedKey element/
     */
    public function __invoke(Document $envelope, WSSESoap $wsse, DOMElement $parent): void;
}
