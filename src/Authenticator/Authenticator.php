<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Ormtopus\DataEntityManager;
use Doomy\Security\Exception\InvalidPasswordException;
use Doomy\Security\Exception\UserBlockedException;
use Doomy\Security\Exception\UserNotFoundException;
use Doomy\Security\Model\User;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;

final readonly class Authenticator implements IAuthenticator
{
    private DataEntityManager $data;

    public function __construct(
        DataEntityManager $data,
    ) {
        $this->data = $data;
    }

    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function authenticate(string $email, string $password, string $userEntityClass = User::class): IIdentity
    {
        $user = $this->data->findOne($userEntityClass, [
            'email' => $email,
        ]);
        if (! $user) {
            throw new UserNotFoundException();
        }

        if ($user->getBlocked()) {
            throw new UserBlockedException();
        }

        if (! password_verify($password, $user->getPassword())) {
            throw new InvalidPasswordException();
        }

        return new Identity($user->getId(), [(string) $user->getRole()], (array) $user);
    }
}
