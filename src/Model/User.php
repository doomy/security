<?php

namespace Doomy\Security\Model;

use Doomy\Repository\Model\Entity;

class User extends Entity
{
    const TABLE = 't_user';

    const IDENTITY_COLUMN = 'USER_ID';

    public $USER_ID;

    public $USER_NAME;

    public $PASSWORD;

    public $FIRST_NAME;

    public $MIDDLE_NAME;

    public $LAST_NAME;

    public $BIRTH_DATE;

    public $CREATED_DATETIME;

    public $CHANGED_DATE;

    public $BLOCKED;

    public $EMAIL;

    public $ROLE;
}
