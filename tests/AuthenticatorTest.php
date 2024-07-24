<?php

declare(strict_types=1);

namespace Doomy\Security\Tests;

use Doomy\EntityCache\EntityCache;
use Doomy\Ormtopus\DataEntityManager;
use Doomy\Repository\EntityFactory;
use Doomy\Repository\Helper\DbHelper;
use Doomy\Repository\RepoFactory;
use Doomy\Repository\TableDefinition\ColumnTypeMapper;
use Doomy\Repository\TableDefinition\TableDefinitionFactory;
use Doomy\Security\Authenticator;
use Doomy\Security\Model\User;
use Doomy\Security\PasswordService;
use Doomy\Testing\AbstractDbAwareTestCase;
use Nette\Security\Identity;
use PHPUnit\Framework\Assert;

final class AuthenticatorTest extends AbstractDbAwareTestCase
{
    private Authenticator $authenticator;

    private DataEntityManager $data;

    private TableDefinitionFactory $tableDefinitionFactory;

    private DbHelper $dbHelper;

    public function __construct(string $name)
    {
        parent::__construct($name);

        $columnTypeMapper = new ColumnTypeMapper();
        $this->tableDefinitionFactory = new TableDefinitionFactory($columnTypeMapper);
        $this->dbHelper = new DbHelper($columnTypeMapper);
        $repoFactory = new RepoFactory($this->connection, new EntityFactory(
            $this->tableDefinitionFactory
        ), $this->dbHelper, $this->tableDefinitionFactory);
        $this->data = new DataEntityManager($repoFactory, new EntityCache());
        $this->authenticator = new Authenticator($this->data);
    }

    protected function setUp(): void
    {
        $userTableDefinition = $this->tableDefinitionFactory->createTableDefinition(User::class);
        $this->connection->query($this->dbHelper->getCreateTable($userTableDefinition));

        $passwordService = new PasswordService();
        $hashedPassword = $passwordService->hashPassword('my-password');

        $user = new User(
            email: 'test@email.com',
            password: $hashedPassword,
            created: new \DateTimeImmutable(),
            changed: new \DateTimeImmutable(),
            role: 'user'
        );
        $this->data->save(User::class, $user);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->connection->query('DROP TABLE t_user');
        parent::tearDown();
    }

    public function testAuthenticateOk(): void
    {
        $identity = $this->authenticator->authenticate(['test@email.com', 'my-password']);
        Assert::assertInstanceOf(Identity::class, $identity);
    }

    public function testInvalidPassword(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid password');
        $this->authenticator->authenticate(['test@email.com', 'incorrect-password']);
    }
}
