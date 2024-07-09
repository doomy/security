<?php

namespace Doomy\Security;

use Doomy\Ormtopus\DataEntityManager;
use Doomy\Security\Model\User;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;

final readonly class Authenticator implements IAuthenticator
{
    private string $salt;

    private DataEntityManager $data;

    /**
     * @param array<string, string> $config
     */
    public function __construct(
        DataEntityManager $data,
        array $config,
        private PasswordService $passwordService
    ) {
        $this->data = $data;
        $this->salt = $config['salt'];
    }

    /**
     * @param string[] $credentials
     */
    public function authenticate(array $credentials): IIdentity
    {
        list($email, $password) = $credentials;

        $passwordHashed = $this->passwordService->hashPassword($password, $this->salt);

        $user = $this->data->findOne($this->getUserModelClass(), [
            'EMAIL' => $email,
            'PASSWORD' => $passwordHashed,
        ]);
        if (! $user) throw new \Exception('Login failed');
        if ($user->BLOCKED == 1) throw new \Exception('Your account has been blocked. Please contact support.');

        return new Identity($user->USER_ID, [(string) $user->ROLE], (array) $user);
    }

    public function getUserIdentity(int $userId): Identity
    {
        $user = $this->data->findOne($this->getUserModelClass(), [
            'USER_ID' => $userId,
        ]);
        return new Identity($user->USER_ID, [(string) $user->ROLE], (array) $user);
    }

    protected function getUserModelClass(): string
    {
        return User::class;
    }
}
