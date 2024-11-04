<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\Model\User;

interface AuthenticatorInterface
{
    /**
     * @template T of User
     * @param array<string, int|string> $headers
     * @param class-string<T> $userEntityClass
     */
    public function authenticateRequest(array $headers, string $userEntityClass = User::class): void;
}
