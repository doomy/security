<?php

declare(strict_types=1);

namespace Doomy\Security\Tests;

use Doomy\Security\Authenticator\DummyAuthenticator;
use Doomy\Security\Exception\InvalidTokenException;
use Doomy\Security\Exception\TokenExpiredException;
use PHPUnit\Framework\TestCase;

final class DummyAuthenticatorTest extends TestCase
{
    public function testOk(): void
    {
        $this->expectNotToPerformAssertions();
        $dummyAuthenticator = new DummyAuthenticator();
        $dummyAuthenticator->authenticate('valid');
    }

    public function testInvalidToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $dummyAuthenticator = new DummyAuthenticator();
        $dummyAuthenticator->authenticate('invalid');
    }

    public function testExpiredToken(): void
    {
        $this->expectException(TokenExpiredException::class);
        $dummyAuthenticator = new DummyAuthenticator();
        $dummyAuthenticator->authenticate('expired');
    }
}
