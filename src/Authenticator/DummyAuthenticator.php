<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\Exception\InvalidTokenException;
use Doomy\Security\Exception\TokenExpiredException;
use Doomy\Security\Model\User;

final class DummyAuthenticator implements AuthenticatorInterface
{
    /**
     * @param array<string, string> $headers
     */
    public function authenticateRequest(array $headers, string $userEntityClass = User::class): void
    {
        if (! array_key_exists('Authorization', $headers)) {
            return;
        }

        if ($headers['Authorization'] === 'Bearer invalid') {
            throw new InvalidTokenException();
        } elseif ($headers['Authorization'] === 'Bearer expired') {
            throw new TokenExpiredException();
        }
    }
}
