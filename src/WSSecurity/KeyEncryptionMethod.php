<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum KeyEncryptionMethod: string
{
    case RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    case RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    case RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
}
