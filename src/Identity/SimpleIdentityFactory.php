<?php

declare(strict_types=1);

namespace Doomy\Security\Identity;

use Nette\Security\SimpleIdentity;

final readonly class SimpleIdentityFactory implements IdentityFactoryInterface
{
    /**
     * @param mixed[] $roles
     * @param mixed[] $data
     */
    public function createIdentity(string|int $id, array $roles, array $data): SimpleIdentity
    {
        return new SimpleIdentity($id, $roles, $data);
    }
}
