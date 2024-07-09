<?php

namespace Doomy\Security\Model;

use Doomy\Repository\Model\Entity;

final class User extends Entity
{
    public const string TABLE = 't_user';

    public const string IDENTITY_COLUMN = 'USER_ID';

    public int $USER_ID;

    public string $USER_NAME;

    public string $PASSWORD;

    public string $FIRST_NAME;

    public string $MIDDLE_NAME;

    public string $LAST_NAME;

    public \DateTimeInterface $BIRTH_DATE;

    public \DateTimeInterface $CREATED_DATETIME;

    public \DateTimeInterface $CHANGED_DATE;

    public bool $BLOCKED;

    public string $EMAIL;

    public string $ROLE;
}
