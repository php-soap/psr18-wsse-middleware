<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum SignatureMethod: string
{
    case RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    case DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    case RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    case RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    case HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
}
