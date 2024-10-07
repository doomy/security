<?php

declare(strict_types=1);

namespace Doomy\Security;

final readonly class LoginResult
{
    public function __construct(
        private readonly string $accessToken,
        private readonly string $refreshToken,
    ) {
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }
}
