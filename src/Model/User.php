<?php

declare(strict_types=1);

namespace Doomy\Security\Model;

use Doomy\Repository\Model\Entity;

final class User extends Entity
{
    public const string TABLE = 't_user';

    public const string IDENTITY_COLUMN = 'USER_ID';

    public int $USER_ID;

    public string $EMAIL;

    public string $PASSWORD;

    public \DateTimeInterface $CREATED_DATETIME;

    public \DateTimeInterface $CHANGED_DATE;

    public bool $BLOCKED;

    public string $ROLE;
}
