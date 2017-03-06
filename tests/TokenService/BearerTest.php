<?php
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Gabriel Somoza
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace SomozaTest\Unit\Psr7\OAuth2Middleware;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Somoza\OAuth2Middleware\TokenService\AbstractTokenService;
use Somoza\OAuth2Middleware\TokenService\Bearer;
use Mockery as m;
use SomozaTest\OAuth2Middleware\TestCase;

/**
 * Class BearerTest
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
class BearerTest extends TestCase
{
    /** @var AbstractProvider|m\Mock */
    private $provider;

    /**
     * setUp
     * @return void
     */
    public function setUp()
    {
        $this->provider = m::mock(AbstractProvider::class);
    }

    public function testConstructorWithoutAccessToken()
    {
        $instance = new Bearer($this->provider);

        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that a dummy token was created
        $token = $method->invoke($instance);
        $this->assertInstanceOf(AccessToken::class, $token);
        /** @var AccessToken $token */
        $this->assertTrue($token->hasExpired());
    }

    public function testConstructorWithAccessToken()
    {
        $token = new AccessToken(['access_token' => '123']);
        $instance = new Bearer($this->provider, $token);
        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that a dummy token was created
        $result = $method->invoke($instance);

        $this->assertSame($token, $result);
    }

    public function testShouldRequestNewAccessTokenIfNoToken()
    {
        $accessToken = m::mock(AccessToken::class, ['getToken' => 'abc']);
        $this->provider->shouldReceive('getAccessToken')
            ->once()
            ->with('client_credentials')
            ->andReturn($accessToken);

        $instance = new Bearer($this->provider); // with an expired token

        $request = new Request('GET', '/secured/resource');
        $instance->authorize($request);

        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that the token was returned
        $result = $method->invoke($instance);

        $this->assertSame($accessToken, $result);
    }

    /**
     * should_skip_requests_with_authorization_header
     * @return void
     *
     * @test
     */
    public function testShouldSkipAuthorizedRequests()
    {
        $instance = new Bearer($this->provider); // with an expired token
        $request = new Request('GET', '/secured/resource', ['Authorization' => 'Bearer 123']);

        $result = $instance->authorize($request);

        $this->assertSame($request, $result);
        $this->provider->shouldNotHaveReceived('getAccessToken');
    }

    public function testShouldRefreshTokenIfExpired()
    {
        $pastTime = time() - 500;
        $oldToken = new AccessToken(['access_token' => '123', 'expires' => $pastTime]);
        $newToken = new AccessToken(['access_token' => 'abc']);

        $this->provider
            ->shouldReceive('getAccessToken')
            ->once()
            ->with('client_credentials')
            ->andReturn($newToken);

        $instance = new Bearer($this->provider, $oldToken);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertResultAuthorizedWithToken($result, $newToken);
    }

    /**
     * should_request_new_access_token_if_expired
     * @test
     */
    public function should_refresh_access_token_if_expired()
    {
        $time = time();
        $oldToken = new AccessToken(['access_token' => '123', 'refresh_token' => '567', 'expires' => $time]);
        $newToken = new AccessToken(['access_token' => 'abc']);

        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->with('refresh_token', ['refresh_token' => '567'])
            ->willReturn($newToken);

        $instance = new Bearer($this->provider, $oldToken);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertResultAuthorizedWithToken($result, $newToken);
    }

    /**
     * should_not_request_new_access_token_if_token_still_valid
     * @test
     */
    public function should_not_request_new_access_token_if_token_has_no_expiration()
    {
        $validToken = new AccessToken(['access_token' => '123']);

        $this->provider->expects($this->never())
            ->method('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $this->invoke($instance, 'authorizeRequest', [$request]);

        $this->assertResultAuthorizedWithToken($result, $validToken);
    }

    /**
     * should_not_request_new_access_token_if_token_still_valid
     * @test
     */
    public function should_not_request_new_access_token_if_token_still_valid()
    {
        $time = time() + 3600;
        $validToken = new AccessToken(['access_token' => '123', 'expires' => $time]);

        $this->provider->expects($this->never())
            ->method('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $this->invoke($instance, 'authorizeRequest', [$request]);

        $this->assertResultAuthorizedWithToken($result, $validToken);
    }

    /**
     * invoke_should_return_function
     * @test
     */
    public function invoke_should_return_function()
    {
        $callback = function() {};

        $instance = new Bearer($this->provider);
        $this->assertTrue(method_exists($instance, '__invoke'));

        $func = $instance->__invoke($callback);

        $this->assertInternalType('callable', $func);
    }

    /**
     * @test
     */
    public function should_invoke_token_callback_if_token_renewed()
    {
        $accessToken = new AccessToken(['access_token' => '123']);
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($accessToken);
        $tokenCallbackCalled = false;

        // the callback that we're testing
        $tokenCallback = function (AccessToken $token, AccessToken $oldToken = null) use (&$tokenCallbackCalled, $accessToken) {
            $tokenCallbackCalled = true;
            $this->assertSame($token, $accessToken);
            $this->assertSame(null, $oldToken);
        };

        $instance = new Bearer($this->provider, null, $tokenCallback);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authorizeRequest', [$request]);

        $this->assertResultAuthorizedWithToken($result, $accessToken);
    }

    /**
     * @test
     */
    public function should_invoke_token_callback_including_old_token_if_token_renewed()
    {
        $oldAccessToken = new AccessToken(['access_token' => 'oldie', 'expires' => time()]);
        $accessToken = new AccessToken(['access_token' => '123']);

        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($accessToken);
        $tokenCallbackCalled = false;

        // the callback that we're testing
        $tokenCallback = function (AccessToken $token, AccessToken $oldToken) use (&$tokenCallbackCalled, $accessToken, $oldAccessToken) {
            $tokenCallbackCalled = true;
            $this->assertSame($token, $accessToken);
            $this->assertSame($oldAccessToken, $oldToken);
        };

        $instance = new Bearer($this->provider, $oldAccessToken, $tokenCallback);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authorizeRequest', [$request]);

        $this->assertResultAuthorizedWithToken($result, $accessToken);
    }

    /**
     * End-to-end test
     *
     * @test
     */
    public function invoke_function_should_authorize()
    {
        $callbackCalled = false;
        $callback = function(RequestInterface $request, array $options) use (&$callbackCalled) {
            $callbackCalled = true;
            $this->assertEquals(['foo' => 'bar'], $options);
            $this->assertTrue($request->hasHeader(Bearer::HEADER_AUTHORIZATION));
            return new Response(); // ok
        };

        $validToken = new AccessToken(['access_token' => 'abc']);
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($validToken);

        $request = new Request('GET', 'http://foo.bar/baz');
        $options = ['foo' => 'bar'];

        /** @var Bearer|\PHPUnit_Framework_MockObject_MockObject $instance */
        $instance = new Bearer($this->provider);
        $func = $instance->__invoke($callback);

        $func($request, $options);

        $this->assertTrue($callbackCalled);
    }

    /**
     * @test
     * Test that authorization url and base access token url are white-listed by default
     */
    public function should_whitelist_base_urls_by_default()
    {
        $this->provider->expects($this->once())
            ->method('getBaseAuthorizationUrl')
            ->willReturn('oauth2/authorize');

        $this->provider->expects($this->once())
            ->method('getBaseAccessTokenUrl')
            ->willReturn('oauth2/token');

        $instance = new Bearer($this->provider);

        /** @var Whitelist $whitelist */
        $whitelist = $this->getPropVal($instance, 'ignoredUris');

        $this->assertTrue($whitelist->allowed('oauth2/authorize'));
        $this->assertTrue($whitelist->allowed('oauth2/token'));
    }

    /**
     * @test
     */
    public function should_check_whitelist()
    {
        $whitelist = new StringWhitelist([
            'url1',
            'url2',
            'url3',
            'url4',
        ]);
        $instance = new Bearer($this->provider, null, null, $whitelist);

        //in white list
        $this->assertTrue($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['url1']));
        $this->assertTrue($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['url2']));
        $this->assertTrue($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['url3']));
        $this->assertTrue($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['url4']));

        //not in white list
        $this->assertFalse($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['url5']));
        $this->assertFalse($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['']));
        $this->assertFalse($this->invoke($instance, 'shouldSkipAuthorizationForUri', [null]));
        $this->assertFalse($this->invoke($instance, 'shouldSkipAuthorizationForUri', ['http://missing.com']));
    }


    /**
     * @test
     */
    public function should_not_authorize_whitelisted_urls()
    {
        $validToken = new AccessToken(['access_token' => '123']);

        $whitelist = new StringWhitelist([
            'https://whitelisted.com',
            'https://another.white.list.com'
        ]);

        $instance = new Bearer($this->provider, $validToken, null, $whitelist);

        //Assert request is not changed for whitelisted url
        $request = new Request('GET', 'https://whitelisted.com');
        $result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertSame($request, $result);

        //Assert request is not changed for whitelisted url
        $request = new Request('GET', 'https://another.white.list.com');
        $result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertSame($request, $result);

        //Assert request is changed for whitelisted url
        $request = new Request('GET', 'https://authorizeme.com');
        $result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertResultAuthorizedWithToken($result, $validToken);
    }

    /**
     * assertResultAuthorizedWithToken
     * @param $result
     * @param $accessToken
     * @return void
     */
    private function assertResultAuthorizedWithToken(RequestInterface $result, AccessToken $accessToken)
    {
        $this->assertTrue($result->hasHeader(Bearer::HEADER_AUTHORIZATION));
        $this->assertContains(Bearer::AUTHENTICATION_SCHEME . ' ' . $accessToken->getToken(), $result->getHeader(Bearer::HEADER_AUTHORIZATION));
    }
}
