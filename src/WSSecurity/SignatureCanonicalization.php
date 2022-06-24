<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

/**
 * Currently, there is no option to configure this in robrichards/wsse.
 * It is hardcoded to C14N
 * TODO : Add it to robrichard's base package before it can be used.
 * @see https://github.com/robrichards/wse-php/blob/c9611f554d88cbd58935d7da901d84093068168c/src/WSSESoap.php#L221-L227
 */
enum SignatureCanonicalization: string
{
    case C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    case C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    case EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
}
