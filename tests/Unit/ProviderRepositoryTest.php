<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\Exceptions\MissingRequiredAttributesException;
use BenBjurstrom\CognitoGuard\ProviderRepository;
use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\UserAttributeService;
use Firebase\JWT\SignatureInvalidException;
use Ramsey\Uuid\Uuid;

class ProviderRepositoryTest extends TestCase
{
    /**
     * @var ProviderRepository
     */
    protected $repository;

    /**
     *
     */
    public function setUp(): void {
        parent::setUp();

        $this->repository = new ProviderRepository($this->app['auth']->createUserProvider('users'));
    }

    /**
     * @test
     */
    public function testGetCognitoUser(){
        $this->app['config']->set('cognito.sso', true);
        $cognitoUuid = Uuid::uuid4()->toString();
        $jwt = 'jwt';
        $attributes = collect([
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);

        $uas = $this->mock(UserAttributeService::class);
        $uas->shouldReceive('getUserAttributesFromToken')
            ->with($jwt)
            ->andReturn($attributes);

        $result = $this->repository->getCognitoUser($cognitoUuid, $jwt);

        $this->assertInstanceOf(User::class, $result);
        $this->assertEquals($cognitoUuid, $result->cognito_uuid);

        $this->assertDatabaseHas('users', [
            'cognito_uuid' => $cognitoUuid,
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);
    }

    /**
     * @test
     */
    public function testCreateSsoUser()
    {
        $this->app['config']->set('cognito.sso', true);
        $cognitoUuid = Uuid::uuid4()->toString();
        $jwt = 'jwt';
        $attributes = collect([
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);

        $uas = $this->mock(UserAttributeService::class);
        $uas->shouldReceive('getUserAttributesFromToken')
            ->with($jwt)
            ->andReturn($attributes);

        $result = $this->repository->createSsoUser($cognitoUuid, $jwt);

        $this->assertInstanceOf(User::class, $result);
        $this->assertEquals($cognitoUuid, $result->cognito_uuid);

        $this->assertDatabaseHas('users', [
            'cognito_uuid' => $cognitoUuid,
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);
    }

    /**
     * @test
     */
    public function testCallSsoRepository()
    {
        $cognitoUuid = Uuid::uuid4()->toString();
        $this->app['config']->set('cognito.sso', true);
        $this->app['config']->set('cognito.sso_repository_class', 'BenBjurstrom\\CognitoGuard\\Tests\\Fixtures\\User');
        $jwt = 'jwt';
        $attributes = collect([
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);

        $uas = $this->mock(UserAttributeService::class);
        $uas->shouldReceive('getUserAttributesFromToken')
            ->with($jwt)
            ->andReturn($attributes);

        $result = $this->repository->createSsoUser($cognitoUuid, $jwt);

        $this->assertInstanceOf(User::class, $result);
        $this->assertEquals($cognitoUuid, $result->cognito_uuid);

        $this->assertDatabaseHas('users', [
            'cognito_uuid' => $cognitoUuid,
            'email' => 'test@example.com',
            'name'  => 'Another Body'
        ]);
    }

    /**
     * @test
     */
    public function testGetAttributes(){
        $jwt = 'jwt';
        $attributes = collect([
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);

        $uas = $this->mock(UserAttributeService::class);
        $uas->shouldReceive('getUserAttributesFromToken')
            ->with($jwt)
            ->andReturn($attributes);

        $result = $this->repository->getAttributes($jwt);

        $this->assertEquals($result, $attributes);
    }

    /**
     * @test
     */
    public function testValidateAttributes(){
        $available = collect([
            'email' => 'test@example.com',
            'name'  => 'Some Body'
        ]);
        $required = collect(['email', 'name']);

        $this->repository->validateAttributes($available, $required);
    }

    /**
     * @test
     */
    public function testValidateAttributesFails(){
        $available = collect([
            'email' => 'test@example.com',
            // 'name'  => 'Some Body'
        ]);
        $required = collect(['email', 'name', 'phone']);

        $this->expectException(MissingRequiredAttributesException ::class);
        $this->expectExceptionMessage('Required attributes (name,phone) were not returned by cognito');

        $this->repository->validateAttributes($available, $required);
    }
}
