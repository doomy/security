<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\Model\User;

final class DummyAuthenticator implements AuthenticatorInterface
{
    public function authenticateRequest(array $headers, string $userEntityClass = User::class): void
    {
    }
}
