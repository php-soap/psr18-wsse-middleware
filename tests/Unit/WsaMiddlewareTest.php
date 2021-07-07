<?php declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Middleware;

use Http\Client\Common\Plugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Mock\Client;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use RobRichards\WsePhp\WSASoap;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use Soap\Xml\Xpath\EnvelopePreset;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath;

final class WsaMiddlewareTest extends TestCase
{
    private PluginClient $client;
    private Client $mockClient;
    private WsaMiddleware $middleware;

    protected function setUp(): void
    {
        $this->middleware = new WsaMiddleware();
        $this->mockClient = new Client(Psr17FactoryDiscovery::findResponseFactory());
        $this->client = new PluginClient($this->mockClient, [$this->middleware]);
    }

    
    public function test_it_is_a_middleware()
    {
        static::assertInstanceOf(Plugin::class, $this->middleware);
    }

    
    public function test_it_adds_wsa_to_the_request_xml()
    {
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $this->client->sendRequest(
            $request = new Request(
            'POST',
            '/endpoint',
            ['SOAPAction' => 'myaction'],
            $soapRequest
        )
        );

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Make sure the response is available:
        static::assertEquals($response, $result);

        // Check structure
        static::assertEquals(1, $xpath->query('//soap:Header/wsa:Action')->count(), 'No WSA Action tag');
        static::assertEquals(1, $xpath->query('//soap:Header/wsa:To')->count(), 'No WSA To tag');
        static::assertEquals(1, $xpath->query('//soap:Header/wsa:MessageID')->count(), 'No WSA MessageID tag');
        static::assertEquals(1, $xpath->query('//soap:Header/wsa:ReplyTo')->count(), 'No WSA ReplyTo tag');
        static::assertEquals(1, $xpath->query('//soap:Header/wsa:ReplyTo/wsa:Address')->count(), 'No WSA ReplyTo Address tag');

        // Check defaults:
        static::assertEquals('myaction', $xpath->query('//soap:Header/wsa:Action')->item(0)->nodeValue);
        static::assertEquals('/endpoint', $xpath->query('//soap:Header/wsa:To')->item(0)->nodeValue);
        static::assertMatchesRegularExpression(
            '/^uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
            $xpath->query('//soap:Header/wsa:MessageID')->item(0)->nodeValue
        );
        static::assertEquals(
            WsaMiddleware::WSA_ADDRESS_ANONYMOUS,
            $xpath->query('//soap:Header/wsa:ReplyTo/wsa:Address')->item(0)->nodeValue
        );
    }

    private function fetchEnvelopeXpath(string $soapBody): Xpath
    {
        $document = Document::fromXmlString($soapBody);

        return $document->xpath(
            new EnvelopePreset($document),
            Xpath\Configurator\namespaces([
                'wsa' => WSASoap::WSANS_2005
            ])
        );
    }
}
