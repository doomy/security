<?php

namespace Doomy\Security;

final readonly class PasswordService
{
    public function hashPassword(string $password, string $alorithm, string $salt): string
    {
        $resource = hash_init($alorithm, HASH_HMAC, $salt);
        hash_update($resource, $password);
        return hash_final($resource);
    }
}