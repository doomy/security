<?php

declare(strict_types=1);

namespace Doomy\Security\Model;

use Doomy\Repository\Model\Entity;
use Doomy\Repository\TableDefinition\Attribute\Column\Identity;
use Doomy\Repository\TableDefinition\Attribute\Column\PrimaryKey;
use Doomy\Repository\TableDefinition\Attribute\Column\Unique;
use Doomy\Repository\TableDefinition\Attribute\Table;

#[Table('t_user')]
class User extends Entity
{
    public function __construct(
        #[Unique]
        private string $email,
        private string $password,
        private \DateTimeInterface $created,
        private \DateTimeInterface $changed,
        private string $role,
        private bool $blocked = false,
        #[Identity]
        #[PrimaryKey]
        private ?int $id = null
    ) {
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function getCreated(): \DateTimeInterface
    {
        return $this->created;
    }

    public function getChanged(): \DateTimeInterface
    {
        return $this->changed;
    }

    // TODO: we should support isBlocked() method in the Entity class
    public function getBlocked(): bool
    {
        return $this->blocked;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getRole(): string
    {
        return $this->role;
    }

    public function setId(?int $id): void
    {
        $this->id = $id;
    }
}
