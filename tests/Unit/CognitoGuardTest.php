<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\CognitoGuard;
use BenBjurstrom\CognitoGuard\ProviderRepository;
use BenBjurstrom\CognitoGuard\TokenService;
use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Http\Request;

class CognitoGuardTest extends TestCase
{

    /**
     * @test
     */
    public function testUser(){
        $user = factory(User::class)->create();
        $jwt  = 'jwt';

        $request = $this->mock(Request::class);
        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $this->mock(TokenService::class, function ($mock) use ($user, $jwt) {
            $mock->shouldReceive('getCognitoUuidFromToken')
                ->with($jwt)
                ->andReturn($user->cognito_uuid);
        });

        $repository = $this->mock(ProviderRepository::class);
        $repository->shouldReceive('getCognitoUser')
            ->with($user->cognito_uuid, $jwt)
            ->andReturn($user);

        $guard = new CognitoGuard($request, $repository);

        $result = $guard->user();
        $this->assertEquals($user->id, $result->id);
        $this->assertTrue($guard->hasUser());
        $this->assertTrue($guard->check());
    }

    /**
     * @test
     */
    public function testUserAlreadySet(){
        $user = factory(User::class)->create();
        $guard = $this->app->make(CognitoGuard::class);
        $guard->setUser($user);

        $result = $guard->user();
        $this->assertEquals($user->id, $result->id);
        $this->assertTrue($guard->hasUser());
        $this->assertTrue($guard->check());
    }

    /**
     *
     */
    public function testUserNoBearer(){
        $request = $this->mock(Request::class);
        $request->shouldReceive('bearerToken')
            ->andReturn(null);

        $guard = $this->app->make(CognitoGuard::class);

        $result = $guard->user();
        $this->assertNull($result);
        $this->assertFalse($guard->hasUser());
        $this->assertFalse($guard->check());
    }

    /**
     * @test
     */
    public function testUserNoUser(){
        $user = factory(User::class)->create();
        $jwt  = 'jwt';

        $request = $this->mock(Request::class);
        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $this->mock(TokenService::class, function ($mock) use ($user, $jwt) {
            $mock->shouldReceive('getCognitoUuidFromToken')
                ->with($jwt)
                ->andReturn($user->cognito_uuid);
        });

        $repository = $this->mock(ProviderRepository::class);
        $repository->shouldReceive('getCognitoUser')
            ->with($user->cognito_uuid, $jwt)
            ->andReturn(null);

        $guard = new CognitoGuard($request, $repository);

        $result = $guard->user();
        $this->assertNull($result);
        $this->assertFalse($guard->hasUser());
        $this->assertFalse($guard->check());
    }
}
