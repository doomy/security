<?php

declare(strict_types=1);

namespace Doomy\Security;

use Doomy\Ormtopus\DataEntityManager;
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
     * @param string[] $credentials
     */
    public function authenticate(array $credentials): IIdentity
    {
        list($email, $password) = $credentials;

        $user = $this->data->findOne(User::class, [
            'email' => $email,
        ]);
        if (! $user) {
            throw new \Exception('User not found');
        }

        if (! password_verify($password, $user->getPassword())) {
            throw new \Exception('Invalid password');
        }

        if ($user->getBlocked()) {
            throw new \Exception('Your account has been blocked. Please contact support.');
        }

        return new Identity($user->getId(), [(string) $user->getRole()], (array) $user);
    }
}
