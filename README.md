# SOAP WSSE/WSA Middleware

This package provides the tools you need in order to add WSSE and WSA security to your PSR-18 based SOAP Transport.

## Installation

```shell
composer install php-soap/psr18-wsse-middleware
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

If you ever had to implement Web Service Security (WSS / WSSE) manually, you know that it is a lot of work to get this one working.
Luckily for you we created an opinionated WSSE middleware that can be used to sign your SOAP requests.

**Usage**
```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;

// Simple:
$wsse = new WsseMiddleware('privatekey.pem', 'publickey.pyb');

// With signed headers. E.g: in combination with WSA:
$wsse = (new WsseMiddleware('privatekey.pem', 'publickey.pyb'))
    ->withAllHeadersSigned();

// With configurable timestamp expiration:
$wsse = (new WsseMiddleware('privatekey.pem', 'publickey.pyb'))
    ->withTimestamp(3600);

// With plain user token:
$wsse = (new WsseMiddleware('privatekey.pem', 'publickey.pyb'))
    ->withUserToken('username', 'password', false);

// With digest user token:
$wsse = (new WsseMiddleware('privatekey.pem', 'publickey.pyb'))
    ->withUserToken('username', 'password', true);

// With end-to-end encryption enabled:
$wsse = (new WsseMiddleware('privatekey.pem', 'publickey.pyb'))
    ->withEncryption('client-x509.pem')
    ->withServerCertificateHasSubjectKeyIdentifier(true);

// Configure your PSR18 client:
$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        $wsse
    ])
);
```
