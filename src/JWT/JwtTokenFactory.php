<?php

declare(strict_types=1);

namespace Doomy\Security\JWT;

use Doomy\Security\JWT\Enum\Issuer;
use Doomy\Security\JWT\Model\JwtToken;

final readonly class JwtTokenFactory
{
    /**
     * @return array<string, int|string>
     */
    public function toPayload(JwtToken $token): array
    {
        return [
            'iss' => $token->getIssuer()
->value,
            'sub' => $token->getUserId(),
            'iat' => $token->getIssuedAt()
                ->getTimestamp(),
            'exp' => $token->getExpiresAt()
                ->getTimestamp(),
        ];
    }

    /**
     * @param array<string, int|string> $payload
     */
    public function fromPayload(array $payload): JwtToken
    {
        return new JwtToken(
            Issuer::from($payload['iss']),
            (int) $payload['sub'],
            new \DateTimeImmutable('@' . $payload['iat']),
            new \DateTimeImmutable('@' . $payload['exp']),
        );
    }
}
