<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Security\Exception\InvalidTokenException;
use Doomy\Security\Exception\TokenExpiredException;
use Doomy\Security\Model\User;
use Nette\Security\IIdentity;

final class DummyAuthenticator implements AuthenticatorInterface
{
    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function authenticate(string $accessToken, string $userEntityClass = User::class): IIdentity
    {
        if ($accessToken === 'invalid') {
            throw new InvalidTokenException();
        } elseif ($accessToken === 'expired') {
            throw new TokenExpiredException();
        }

        return new class() implements IIdentity {
            public function getId(): int|string
            {
                return 1;
            }

            /**
             * @return string[]
             */
            public function getRoles(): array
            {
                return ['user'];
            }
        };
    }
}
