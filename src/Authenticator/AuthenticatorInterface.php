<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\LoginResult;
use Doomy\Security\Model\User;

interface AuthenticatorInterface
{
    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function login(string $email, string $password, string $userEntityClass = User::class): LoginResult;

    /**
     * @template T of User
     * @param array<string, int|string> $headers
     * @param class-string<T> $userEntityClass
     */
    public function authenticateRequest(array $headers, string $userEntityClass = User::class): void;
}
