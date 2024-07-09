<?php

namespace Doomy\Security;

final readonly class PasswordService
{
    public function hashPassword(string $password, string $salt): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'salt' => $salt,
        ]);
    }
}