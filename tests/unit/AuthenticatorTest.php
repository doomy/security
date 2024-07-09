<?php

namespace unit;

use Doomy\Ormtopus\DataEntityManager;
use Doomy\Security\Authenticator;
use Doomy\Security\Model\User;
use Mockery;
use Nette\Security\Identity;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase
{
    public function testAuthenticate(): void
    {
        $data = Mockery::mock(DataEntityManager::class);
        $listener = Mockery::mock();

        $authenticator = new TestAuthenticator($data, [
            'salt' => 'mock-salt',
        ]);
        $authenticator->injectListener($listener);

        $credentials = ['mock-email', 'mock-password'];

        $user = $this->getMockUser();

        $listener->shouldReceive('create_hashed_password')
            ->with('mock-password', TestAuthenticator::ALGO)
            ->once()
            ->andReturn('mock-hashed-password');
        $data->shouldReceive('findOne')
            ->with(User::class, [
                'EMAIL' => 'mock-email',
                'PASSWORD' => 'mock-hashed-password',
            ])
            ->once()
            ->andReturn($user);

        $identity = $authenticator->authenticate($credentials);
        $this->assertUserIdentity($user, $identity);

        Mockery::mock();
    }

    public function testAuthenticateNoUser(): void
    {
        $data = Mockery::mock(DataEntityManager::class);
        $listener = Mockery::mock();

        $authenticator = new TestAuthenticator($data, [
            'salt' => 'mock-salt',
        ]);
        $authenticator->injectListener($listener);

        $credentials = ['mock-email', 'mock-password'];

        $listener->shouldReceive('create_hashed_password')
            ->with('mock-password', TestAuthenticator::ALGO)
            ->once()
            ->andReturn('mock-hashed-password');
        $data->shouldReceive('findOne')
            ->with(User::class, [
                'EMAIL' => 'mock-email',
                'PASSWORD' => 'mock-hashed-password',
            ])
            ->once()
            ->andReturn(NULL);

        try {
            $authenticator->authenticate($credentials);
            $this->assertTrue(FALSE); // this should not happen
        } catch (\Exception $e) {
            $this->assertEquals('Login failed', $e->getMessage(), 'exception message ok');
        }

        Mockery::mock();
    }

    public function testAuthenticateUserBlocked(): void
    {
        $data = Mockery::mock(DataEntityManager::class);
        $listener = Mockery::mock();

        $authenticator = new TestAuthenticator($data, [
            'salt' => 'mock-salt',
        ]);
        $authenticator->injectListener($listener);

        $credentials = ['mock-email', 'mock-password'];

        $user = $this->getMockUser();
        $user->BLOCKED = 1;

        $listener->shouldReceive('create_hashed_password')
            ->with('mock-password', TestAuthenticator::ALGO)
            ->once()
            ->andReturn('mock-hashed-password');
        $data->shouldReceive('findOne')
            ->with(User::class, [
                'EMAIL' => 'mock-email',
                'PASSWORD' => 'mock-hashed-password',
            ])
            ->once()
            ->andReturn($user);

        try {
            $authenticator->authenticate($credentials);
            $this->assertTrue(FALSE); // this should not happen
        } catch (\Exception $e) {
            $this->assertEquals(
                'Your account has been blocked. Please contact support.',
                $e->getMessage(),
                'exception message ok'
            );
        }

        Mockery::mock();
    }

    public function testGetUserIdentity(): void
    {
        $data = Mockery::mock(DataEntityManager::class);

        $authenticator = new Authenticator($data, [
            'salt' => 'mock-salt',
        ]);

        $user = $this->getMockUser();

        $data->shouldReceive('findOne')->with(User::class, [
            'USER_ID' => $user->USER_ID,
        ])->once()->andReturn($user);

        $identity = $authenticator->getUserIdentity($user->USER_ID);
        $this->assertUserIdentity($user, $identity);

        Mockery::close();
    }

    private function getMockUser(): User
    {
        $user = Mockery::mock(User::class);
        $user->USER_ID = 123;
        $user->ROLE = 'mock-role';

        return $user;
    }

    private function assertUserIdentity(User $user, Identity $identity): void
    {
        $this->assertInstanceOf(Identity::class, $identity, 'Identity class');
        $this->assertEquals($user->USER_ID, $identity->getId(), 'user id matches');
        $roles = $identity->getRoles();
        $role = array_shift($roles);
        $this->assertEquals($user->ROLE, $role, 'Role present' );
    }
}

class TestAuthenticator extends Authenticator
{
    private $listener;

    const ALGO = 'mock-algo';

    public function create_hashed_password($data, $algorithm): string
    {
        return $this->listener->create_hashed_password($data, $algorithm);
    }

    public function injectListener($listener): void
    {
        $this->listener = $listener;
    }
}
