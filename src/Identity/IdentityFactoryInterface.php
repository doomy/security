<?php

declare(strict_types=1);

namespace Doomy\Security\Identity;

use Nette\Security\IIdentity;

interface IdentityFactoryInterface
{
    /**
     * @param mixed[] $roles
     * @param mixed[] $data
     */
    public function createIdentity(string|int $id, array $roles, array $data): IIdentity;
}
