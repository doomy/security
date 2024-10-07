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
use Doomy\Security\Authenticator\Authenticator;
use Doomy\Security\Exception\InvalidPasswordException;
use Doomy\Security\Exception\UserBlockedException;
use Doomy\Security\Exception\UserNotFoundException;
use Doomy\Security\JWT\JwtService;
use Doomy\Security\JWT\JwtTokenFactory;
use Doomy\Security\LoginResult;
use Doomy\Security\Model\User;
use Doomy\Security\PasswordService;
use Doomy\Testing\AbstractDbAwareTestCase;
use Nette\Security\IIdentity;
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
        $jwtService = new JwtService('my-jwt-secret', new JwtTokenFactory());
        $this->authenticator = new Authenticator($this->data, $jwtService);
    }

    protected function setUp(): void
    {
        $userTableDefinition = $this->tableDefinitionFactory->createTableDefinition(User::class);
        $this->connection->query($this->dbHelper->getCreateTable($userTableDefinition));

        $passwordService = new PasswordService();
        $hashedPassword = $passwordService->hashPassword('my-password');

        $user = new User(
            id: 123,
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

    public function testLoginOk(): void
    {
        $loginResult = $this->authenticator->login('test@email.com', 'my-password');
        Assert::assertInstanceOf(LoginResult::class, $loginResult);
        Assert::assertIsString($loginResult->getAccessToken());
        Assert::assertIsString($loginResult->getRefreshToken());
    }

    public function testValidationOk(): void
    {
        $loginResult = $this->authenticator->login('test@email.com', 'my-password');
        $identity = $this->authenticator->authenticate($loginResult->getAccessToken());
        Assert::assertInstanceOf(IIdentity::class, $identity);
        Assert::assertEquals(123, $identity->getId());
    }

    public function testInvalidPassword(): void
    {
        $this->expectException(InvalidPasswordException::class);
        $this->authenticator->login('test@email.com', 'incorrect-password');
    }

    public function testBlockedUser(): void
    {
        $this->expectException(UserBlockedException::class);
        $this->connection->query('UPDATE t_user SET blocked = 1');
        $this->authenticator->login('test@email.com', 'incorrect-password');
    }

    public function testUserNotFound(): void
    {
        $this->expectException(UserNotFoundException::class);
        $this->authenticator->login('non-existing-email', 'incorrect-password');
    }
}
