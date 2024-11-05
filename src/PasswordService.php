<?php

declare(strict_types=1);

namespace Doomy\Security;

use Doomy\Security\Password\Exception\PasswordTooWeakException;
use ZxcvbnPhp\Zxcvbn;

final readonly class PasswordService
{
    public function __construct(
        private Zxcvbn $zxcvbn
    ) {
    }

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public function validatePasswordStrength(string $password): void
    {
        if ($this->zxcvbn->passwordStrength($password)['score'] < 3) {
            throw new PasswordTooWeakException();
        }
    }
}
