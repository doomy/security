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
use Doomy\Security\Exception\AuthenticationFailedException;
use Doomy\Security\Exception\InvalidPasswordException;
use Doomy\Security\Exception\InvalidTokenException;
use Doomy\Security\Exception\TokenExpiredException;
use Doomy\Security\Exception\UserBlockedException;
use Doomy\Security\Exception\UserNotFoundException;
use Doomy\Security\Identity\SimpleIdentityFactory;
use Doomy\Security\JWT\Enum\Issuer;
use Doomy\Security\JWT\JwtService;
use Doomy\Security\JWT\JwtTokenFactory;
use Doomy\Security\JWT\Model\JwtToken;
use Doomy\Security\JWT\Overload\JWT;
use Doomy\Security\LoginResult;
use Doomy\Security\Model\User;
use Doomy\Security\PasswordService;
use Doomy\Testing\AbstractDbAwareTestCase;
use Nette\Security\IIdentity;
use PHPUnit\Framework\Assert;
use function PHPUnit\Framework\assertInstanceOf;

final class AuthenticatorTest extends AbstractDbAwareTestCase
{
    private Authenticator $authenticator;

    private DataEntityManager $data;

    private TableDefinitionFactory $tableDefinitionFactory;

    private DbHelper $dbHelper;

    private JwtService $jwtService;

    private JwtTokenFactory $jwtTokenFactory;

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
        $this->jwtTokenFactory = new JwtTokenFactory();
        $this->jwtService = new JwtService('my-jwt-secret', $this->jwtTokenFactory);
        $simpleIdentityFactory = new SimpleIdentityFactory();
        $this->authenticator = new Authenticator($this->data, $this->jwtService, $simpleIdentityFactory);
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
        Assert::assertInstanceOf(JwtToken::class, $this->jwtService->decodeToken($loginResult->getAccessToken()));
        Assert::assertInstanceOf(JwtToken::class, $this->jwtService->decodeToken($loginResult->getRefreshToken()));
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

    public function testAuthenticationOk(): void
    {
        $accesToken = $this->jwtService->generateAccessToken(123);
        $identity = $this->authenticator->authenticate($accesToken);
        Assert::assertInstanceOf(IIdentity::class, $identity);
        Assert::assertEquals(123, $identity->getId());
    }

    public function testAuthenticationInvalidToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->authenticator->authenticate('invalid-token');
    }

    public function testAuthenticationExpiredToken(): void
    {
        $token = new JwtToken(
            issuer: Issuer::Doomy,
            userId: 123,
            issuedAt: new \DateTimeImmutable('-1 week'),
            expiresAt: new \DateTimeImmutable('-1 week')
        );
        $payload = $this->jwtTokenFactory->toPayload($token);
        $accessToken = JWT::encode($payload, 'my-jwt-secret', 'HS256');
        $this->expectException(TokenExpiredException::class);
        $this->authenticator->authenticate($accessToken);
    }

    public function testAuthenticationUserNotFound(): void
    {
        $this->expectException(UserNotFoundException::class);
        $token = $this->jwtService->generateAccessToken(999);
        $this->authenticator->authenticate($token);
    }

    public function testAuthenticationBlockedUser(): void
    {
        $this->expectException(UserBlockedException::class);
        $this->connection->query('UPDATE t_user SET blocked = 1');
        $token = $this->jwtService->generateAccessToken(123);
        $this->authenticator->authenticate($token);
    }

    public function testRenewAccessToken(): void
    {
        $refreshToken = $this->jwtService->generateRefreshToken(123);
        $accessTokenRaw = $this->authenticator->renewAccessToken($refreshToken, User::class);
        $accessToken = $this->jwtService->decodeToken($accessTokenRaw);
        Assert::assertInstanceOf(JwtToken::class, $accessToken);
        Assert::assertGreaterThan(new \DateTime(), $accessToken->getExpiresAt());
    }

    public function testRenewAccessTokenExpired(): void
    {
        $refreshToken = new JwtToken(
            issuer: Issuer::Doomy,
            userId: 123,
            issuedAt: new \DateTimeImmutable('-1 week'),
            expiresAt: new \DateTimeImmutable('-1 week')
        );
        $payload = $this->jwtTokenFactory->toPayload($refreshToken);
        $refreshTokenRaw = JWT::encode($payload, 'my-jwt-secret', 'HS256');
        $this->expectException(TokenExpiredException::class);
        $this->authenticator->renewAccessToken($refreshTokenRaw, User::class);
    }

    public function testRenewAccessTokenInvalidToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->authenticator->renewAccessToken('invalid-token', User::class);
    }

    public function testRenewAccessTokenUserNotFound(): void
    {
        $this->expectException(UserNotFoundException::class);
        $refreshToken = $this->jwtService->generateRefreshToken(999);
        $this->authenticator->renewAccessToken($refreshToken, User::class);
    }

    public function testRenewAccessTokenBlockedUser(): void
    {
        $this->expectException(UserBlockedException::class);
        $this->connection->query('UPDATE t_user SET blocked = 1');
        $refreshToken = $this->jwtService->generateRefreshToken(123);
        $this->authenticator->renewAccessToken($refreshToken, User::class);
    }

    public function testIdentityNotSet(): void
    {
        $this->expectException(\LogicException::class);
        $this->authenticator->getIdentity();
    }

    public function testIdentitySet(): void
    {
        $accesToken = $this->jwtService->generateAccessToken(123);
        $this->authenticator->authenticate($accesToken);
        assertInstanceOf(IIdentity::class, $this->authenticator->getIdentity());
    }

    public function testRequestAuthenticationOk(): void
    {
        $this->expectNotToPerformAssertions();
        $accesToken = $this->jwtService->generateAccessToken(123);
        $headers = [
            'Authorization' => 'Bearer ' . $accesToken,
        ];
        $this->authenticator->authenticateRequest($headers);
    }

    public function testRequestAuthenticationInvalidToken(): void
    {
        $headers = ['Authorization' => 'Bearer XXXXXXX'];

        try {
            $this->authenticator->authenticateRequest($headers);
        } catch (AuthenticationFailedException $exception) {
            Assert::assertInstanceOf(InvalidTokenException::class, $exception->getPreviousException());
        }

    }
}