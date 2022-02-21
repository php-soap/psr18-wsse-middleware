<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum DigestMethod: string
{
    case SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    case SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    case RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';
}
