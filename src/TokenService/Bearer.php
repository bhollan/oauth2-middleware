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

namespace Somoza\OAuth2Middleware\TokenService;

use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;

/**
 * Bearer PSR7 Middleware
 *
 * @author Gabriel Somoza <gabriel@somoza.me>
 *
 * @see https://tools.ietf.org/html/rfc6750
 */
final class Bearer extends AbstractTokenService
{
    /** @string Name of the authorization header injected into the request */
    const HEADER_AUTHORIZATION = 'Authorization';

    /** @string Access Token type */
    const TOKEN_TYPE = 'Bearer';

    /**
     * @inheritdoc
     */
    public function isAuthorized(RequestInterface $request): bool
    {
        return $request->hasHeader(self::HEADER_AUTHORIZATION);
    }

    /**
     * @inheritdoc
     */
    protected function requestAccessToken(): AccessToken
    {
        return $this->getProvider()->getAccessToken(self::GRANT_CLIENT_CREDENTIALS);
    }

    /**
     * Returns an authorized copy of the request. Only gets called when necessary (i.e. not if the request is already
     * authorized), and always with a valid (fresh) Access Token. However, it SHOULD be idempotent.
     *
     * @param RequestInterface $request An unauthorized request
     *
     * @return RequestInterface An authorized copy of the request
     */
    protected function getAuthorizedRequest(RequestInterface $request): RequestInterface
    {
        /** @var RequestInterface $request */
        $request = $request->withHeader(
            self::HEADER_AUTHORIZATION,
            $this->getAuthorizationString()
        );

        return $request;
    }

    /**
     * @return string
     */
    private function getAuthorizationString(): string
    {
        return self::TOKEN_TYPE . ' ' . $this->getAccessToken()->getToken();
    }
}
