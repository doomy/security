<?php


namespace Doomy\Security;

use Doomy\Security\Model\User;
use Doomy\Ormtopus\DataEntityManager;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;

class Authenticator implements IAuthenticator
{
    private $salt;
    const ALGO = 'SHA512';
    private DataEntityManager $data;

    public function __construct(DataEntityManager $data, array $config) {
        $this->data = $data;
        $this->salt = $config['salt'];
    }

    public function authenticate(array $credentials): IIdentity
    {
        list($email, $password) = $credentials;

        $passwordHashed = $this->create_hashed_password($password, static::ALGO);

        $user = $this->data->findOne($this->getUserModelClass(), ['EMAIL' => $email, 'PASSWORD' => $passwordHashed]);
        if (!$user) throw new \Exception('Login failed');
        if ($user->BLOCKED == 1) throw new \Exception('Your account has been blocked. Please contact support.');

        return new Identity($user->USER_ID, [(string)$user->ROLE], (array)$user);
    }

    public function create_hashed_password($data, $algorithm) {
        $resource = hash_init($algorithm, HASH_HMAC, $this->salt);
        hash_update($resource, $data);
        $hashed_value = hash_final($resource);
        return $hashed_value;
    }

    public function getUserIdentity($userId): Identity
    {
        $user = $this->data->findOne($this->getUserModelClass(), ['USER_ID' => $userId]);
        return new Identity($user->USER_ID, [(string)$user->ROLE], (array)$user);
    }

    protected function getUserModelClass(): string
    {
        return User::class;
    }
}
