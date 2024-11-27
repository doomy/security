<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\Model\User;
use Nette\Security\IIdentity;

interface AuthenticatorInterface
{
    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function authenticate(string $accessToken, string $userEntityClass = User::class): IIdentity;
}
