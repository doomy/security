<?php

declare(strict_types=1);

namespace Doomy\Security\JWT\Model;

use Doomy\Security\JWT\Enum\Issuer;

final readonly class JwtToken
{
    public function __construct(
        private Issuer $issuer,
        private int $userId,
        private \DateTimeInterface $issuedAt,
        private \DateTimeInterface $expiresAt,
    ) {
    }

    public function getIssuer(): Issuer
    {
        return $this->issuer;
    }

    public function getUserId(): int
    {
        return $this->userId;
    }

    public function getIssuedAt(): \DateTimeInterface
    {
        return $this->issuedAt;
    }

    public function getExpiresAt(): \DateTimeInterface
    {
        return $this->expiresAt;
    }
}
