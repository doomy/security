<?php

declare(strict_types=1);

namespace Doomy\Security\Tests;

use PHPUnit\Framework\TestCase;

final class PasswordServiceTest extends TestCase
{
    public function testWeakPassword(): void
    {
        $this->expectException(\Doomy\Security\Password\Exception\PasswordTooWeakException::class);
        $passwordService = new \Doomy\Security\PasswordService(new \ZxcvbnPhp\Zxcvbn());
        $passwordService->validatePasswordStrength('password');
    }

    public function testWeakPasswordCz(): void
    {
        $this->expectException(\Doomy\Security\Password\Exception\PasswordTooWeakException::class);
        $passwordService = new \Doomy\Security\PasswordService(new \ZxcvbnPhp\Zxcvbn());
        $passwordService->validatePasswordStrength('povazovan');
    }
}
