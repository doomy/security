<?php

declare(strict_types=1);

namespace Doomy\Security\Authenticator;

use Doomy\Ormtopus\DataEntityManager;
use Doomy\Security\Exception\InvalidPasswordException;
use Doomy\Security\Exception\UserBlockedException;
use Doomy\Security\Exception\UserNotFoundException;
use Doomy\Security\JWT\JwtService;
use Doomy\Security\LoginResult;
use Doomy\Security\Model\User;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;

final readonly class Authenticator implements IAuthenticator
{
    public function __construct(
        private DataEntityManager $data,
        private JwtService $jwtService,
    ) {
    }

    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function login(string $email, string $password, string $userEntityClass = User::class): LoginResult
    {
        $user = $this->data->findOne($userEntityClass, [
            'email' => $email,
        ]);
        if (! $user || $user->getId() === null) {
            throw new UserNotFoundException();
        }

        if ($user->getBlocked()) {
            throw new UserBlockedException();
        }

        if (! password_verify($password, $user->getPassword())) {
            throw new InvalidPasswordException();
        }

        $accessToken = $this->jwtService->generateAccessToken($user->getId());
        $refreshToken = $this->jwtService->generateRefreshToken($user->getId());

        return new LoginResult($accessToken, $refreshToken);
    }

    /**
     * @template T of User
     * @param class-string<T> $userEntityClass
     */
    public function authenticate(string $accessToken, string $userEntityClass = User::class): IIdentity
    {
        $accessTokenDecoded = $this->jwtService->validateToken($accessToken);
        $userId = $accessTokenDecoded->getUserId();

        $user = $this->data->findById($userEntityClass, $userId);
        if (! $user) {
            throw new UserNotFoundException();
        }

        if ($user->getBlocked()) {
            throw new UserBlockedException();
        }

        return new Identity($user->getId(), [(string) $user->getRole()], (array) $user);
    }
}
