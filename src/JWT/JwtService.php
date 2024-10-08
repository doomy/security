<?php

declare(strict_types=1);

namespace Doomy\Security\JWT;

use Doomy\Security\JWT\Enum\Issuer;
use Doomy\Security\JWT\Model\JwtToken;
use Doomy\Security\JWT\Overload\JWT;
use Firebase\JWT\Key;

final readonly class JwtService
{
    public const TTL_1_HOUR = 3600;

    public const TTL_1_WEEK = 604800;

    public function __construct(
        private string $jwtSecret,
        private JwtTokenFactory $tokenFactory,
    ) {
    }

    public function generateAccessToken(int $userId): string
    {
        $token = new JwtToken(Issuer::Doomy, $userId, new \DateTimeImmutable(), new \DateTimeImmutable(
            '+' . self::TTL_1_HOUR . ' seconds'
        ));

        return JWT::encode($this->tokenFactory->toPayload($token), $this->jwtSecret, 'HS256');
    }

    public function generateRefreshToken(int $userId): string
    {
        $token = new JwtToken(Issuer::Doomy, $userId, new \DateTimeImmutable(), new \DateTimeImmutable(
            '+' . self::TTL_1_WEEK . ' seconds'
        ));
        return JWT::encode($this->tokenFactory->toPayload($token), $this->jwtSecret, 'HS256');
    }

    public function decodeToken(string $token): JwtToken
    {
        $rawToken = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
        return $this->tokenFactory->fromPayload((array) $rawToken);
    }
}
