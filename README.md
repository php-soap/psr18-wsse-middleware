# SOAP WSSE/WSA Middleware

This package provides the tools you need in order to add WSSE and WSA security to your PSR-18 based SOAP Transport.

# Want to help out? 💚

- [Become a Sponsor](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#sponsor)
- [Let us do your implementation](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#let-us-do-your-implementation)
- [Contribute](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#contribute)
- [Help maintain these packages](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#maintain)

Want more information about the future of this project? Check out this list of the [next big projects](https://github.com/php-soap/.github/blob/main/PROJECTS.md) we'll be working on.

# Installation

```shell
composer require php-soap/psr18-wsse-middleware
```

This package includes the [php-soap/psr18-transport](https://github.com/php-soap/psr18-transport/) package and is meant to be used together with it.
It is a middleware wrapper for the [wse-php package of robrichards](https://github.com/robrichards/wse-php) package. 

## Usage

### WsaMiddleware

If your remote server expects Web Service Addressing (WSA) headers to be available in your request,
you can activate this middleware.
The middleware is a light wrapper that makes it easy to use in your application.

In case you need [WSA w3c 2005 based Web Service Addressing](https://www.w3.org/TR/2005/CR-ws-addr-soap-20050817/#soaphttp), you should use WsaMiddleware2005.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use Soap\Psr18WsseMiddleware\WsaMiddleware2005;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsaMiddleware(),
        // OR
        new WsaMiddleware2005(),
    ])
);
```

### WsseMiddleware

Oh boy ... WS-Security ... can be a real pain !
This package aims for being as flexible as possible and provides you the tools you need to correctly configure Web Service Security.
The components are shaped based on the [WS-Security UI inside SoapUI](https://www.soapui.org/docs/soapui-projects/ws-security/).
This enables you to configure everything the way your SOAP server wants you to!
If you have a working config on SoapUI, you can transform it to PHP code by following the entries and their configurations. 

*Usage:*

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware([$entries])
    ])
);
```

The WSSE middleware can be built out of multiple configurable entries:

* BinarySecurityToken
* Decryption
* Encryption
* SamlAssertion
* Signature
* Timestamp
* Username

Underneath, there are some common examples on how to configure the `$wsseMiddleware`.

#### Adding a username and password

Some services require you to add a username and optionally a password.
This can be done with following middleware.

```php
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry;

$wsseMiddleware = new WsseMiddleware(
    outgoing: [
        (new Entry\Username($user))
            ->withPassword('xxx')
            ->withDigest(false),
    ]
);
```

### Key stores

This package provides a couple of `Key` wrappers that can be used to pass private / public keys:

* `KeyStore\Certificate`: Contains a public X.509 certificate in PEM format.
* `KeyStore\Key`: Contains a PKCS_8 private key in PEM format.
* `KeyStore\ClientCertificate`: Contains both a public X.509 certificate and PKCS_8 private key in PEM format.

Example:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

$privKey = Key::fromFile('security_token.priv')->withPassphrase('xxx'); // Regular private key (not wrapped in X509)
$pubKey = Certificate::fromFile('security_token.pub'); // Public X509 cert

// or:

$bundle = ClientCertificate::fromFile('client-certificate.pem')->withPassphrase('xxx');
$privKey = $bunlde->privateKey();
$pubKey = $bunlde->publicCertificate();
```

In case of a p12 certificate: convert it to a private key and public X509 certificate first:

```bash
openssl pkcs12 -in your.p12 -out security_token.pub -clcerts -nokeys
openssl pkcs12 -in your.p12 -out security_token.priv -nocerts -nodes
```

#### Signing a SOAP request with PKCS12 or X509 certificate.

This is one of the most common implementation of WSS out there.
You are granted a certificate by the soap service with which you need to fetch data.

Next, you can configure the middleware like this:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry;

$privKey = Key::fromFile('security_token.priv')->withPassphrase('xxx');
$pubKey = Certificate::fromFile('security_token.pub');

$wsseMiddleware = new WsseMiddleware(
    outgoing: [
        new Entry\Timestamp(60),
        new Entry\BinarySecurityToken($pubKey),
        (new Entry\Signature(
            $privKey,
            new KeyIdentifier\BinarySecurityTokenIdentifier()
        ))
            ->withSignatureMethod(SignatureMethod::RSA_SHA256)
            ->withDigestMethod(DigestMethod::SHA256)
            ->withSignAllHeaders(true)
            ->withSignBody(true)
    ]
);
```

This example can also be used in combination with signing and username authentication.

#### Authorize a SOAP request with a SAML assertion

Another common implementation is authentication through a WS-Trust compliant STS instance.
In this case, you first have to fetch a SAML assertion from the STS service.
Most of them require you to sign the request with a X509 certificate.
This can be done with the middleware above.

Once you received back your SAML assertion, you have to pass it to the webservice you want to contact.
A common configuration for passing the SAML assertion might look like this:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\document_element;

$privKey = Key::fromFile('security_token.priv')->withPassphrase('xxx');

// These are provided through the STS service.
$samlAssertion = Document::fromXmlString(<<<EOXML
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="xxxx" />
EOXML
);
$samlAssertionId = $samlAssertion->locate(document_element())->getAttribute('AssertionID');

$wsseMiddleware = new WsseMiddleware(
    outgoing: [
        new Entry\Timestamp(60),
        (new Entry\Signature(
            $privKey,
            new KeyIdentifier\SamlKeyIdentifier($samlAssertionId)
        ))
            ->withSignatureMethod(SignatureMethod::RSA_SHA256)
            ->withDigestMethod(DigestMethod::SHA256)
            ->withSignAllHeaders(true)
            ->withSignBody(true)
            ->withInsertBefore(false),
        new Entry\SamlAssertion($samlAssertion),
    ]
);
```

#### Encrypt sensitive data

Some services require you to encrypt sensitive parts of the request and decrypt sensitive parts of the response.
In this case, you can add your public key to the request, encrypt the payload and send it over the wire.
Incoming responses will be encrypted with your public key and kan be decrypted by using your private key.


Encryption contains a [known bug](https://github.com/robrichards/wse-php/pull/67) in the underlying [robrichards/wse-php](https://github.com/robrichards/wse-php) library.
Since a fix has not been merged yet, you can apply a patch like this:

```bash
composer require --dev cweagans/composer-patches
```

```json
{
  "extra": {
    "patches": {
      "robrichards/wse-php": {
        "Fix encryption bug": "https://patch-diff.githubusercontent.com/raw/robrichards/wse-php/pull/67.diff"
      }
    }
  }
}
```

The configuration for encryption looks like this:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry;

$privKey = Key::fromFile('security_token.priv')->withPassphrase('xxx'); // Private key
$pubKey = Certificate::fromFile('security_token.pub'); // Public X509 cert
$signKey = Certificate::fromFile('sign-key.pem'); // X509 cert for signing. Could be the same as $pubKey.

$wsseMiddleware = new WsseMiddleware(
    outgoing: [
        new Entry\Timestamp(60),
        new Entry\BinarySecurityToken($pubKey),
        (new Entry\Signature(
            $privKey,
            new KeyIdentifier\BinarySecurityTokenIdentifier()
        ))
        (new Entry\Encryption(
            $signKey,
            new KeyIdentifier\X509SubjectKeyIdentifier($signKey)
        ))
            ->withKeyEncryptionMethod(KeyEncryptionMethod::RSA_OAEP_MGF1P)
            ->withDataEncryptionMethod(DataEncryptionMethod::AES256_CBC)
    ],
    incoming: [
        new Entry\Decryption($privKey)
    ]
);
```

Note: Encryption only can also be done without adding a signature.
