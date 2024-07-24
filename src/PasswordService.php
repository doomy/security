<?php

declare(strict_types=1);

namespace Doomy\Security;

final readonly class PasswordService
{
    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }
}
