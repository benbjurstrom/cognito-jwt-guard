<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\CognitoGuard;
use BenBjurstrom\CognitoGuard\Exceptions\MethodNotSupportedException;
use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\ProviderRepository;
use BenBjurstrom\CognitoGuard\TokenService;
use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use Firebase\JWT\JWK;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;

class CognitoGuardTest extends TestCase
{

    /**
     * @test
     */
    public function testGuardFailsBecauseNoUser(){
        $jtb    = $this->getJwtTestBundle();

        Route::get('test', function () {
            return auth()->user();
        })->middleware(SubstituteBindings::class)->middleware('auth');

        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        $result = $this->getJson('/test', [
            'Authorization' => 'Bearer' . ' ' . $jtb->jwt,
        ]);

        $this->assertEquals(401, $result->getStatusCode());
        $result->assertJsonFragment(['message' => 'Unauthenticated.']);
        $result->assertUnauthorized();
    }

    /**
     * @test
     */
    public function testGuardAuthorizesUser(){
        $jtb    = $this->getJwtTestBundle();
        $user = User::factory()->create();
        $user->cognito_uuid = $jtb->sub;
        $user->save();

        Route::get('test', function () {
            return auth()->user();
        })->middleware(SubstituteBindings::class)->middleware('auth');

        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        $this->getJson('/test', [
            'Authorization' => 'Bearer' . ' ' . $jtb->jwt,
        ])->assertSuccessful()
        ->assertJsonFragment([
            'id' => $user->id,
            'cognito_uuid' => $user->cognito_uuid,
        ]);
    }

    /**
     * @test
     */
    public function testUserMethodReturnsUser(){
        $user = User::factory()->create();
        $jwt  = 'jwt';

        $request = $this->mock(Request::class);
        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $this->mock(TokenService::class, function ($mock) use ($user, $jwt, $request) {
            $mock->shouldReceive('getTokenFromRequest')
                ->with($request)
                ->andReturn($jwt);

            $mock->shouldReceive('getCognitoUuidFromToken')
                ->with($jwt)
                ->andReturn($user->cognito_uuid);
        });

        $repository = $this->mock(ProviderRepository::class);
        $repository->shouldReceive('getCognitoUser')
            ->with($user->cognito_uuid)
            ->andReturn($user);

        $guard = new CognitoGuard($repository, $request);

        $result = $guard->user();
        $this->assertEquals($user->id, $result->id);
        $this->assertTrue($guard->hasUser());
        $this->assertTrue($guard->check());
    }

    /**
     * @test
     */
    public function testUserAlreadySet(){
        $user = User::factory()->create();
        $guard = $this->app->make(CognitoGuard::class);
        $guard->setUser($user);

        $result = $guard->user();
        $this->assertEquals($user->id, $result->id);
        $this->assertTrue($guard->hasUser());
        $this->assertTrue($guard->check());
    }

    /**
     * @test
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
        $user = User::factory()->create();
        $jwt  = 'jwt';

        $request = $this->mock(Request::class);
        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $this->mock(TokenService::class, function ($mock) use ($user, $jwt, $request) {
            $mock->shouldReceive('getTokenFromRequest')
                ->with($request)
                ->andReturn($jwt);

            $mock->shouldReceive('getCognitoUuidFromToken')
                ->with($jwt)
                ->andReturn($user->cognito_uuid);
        });

        $repository = $this->mock(ProviderRepository::class);
        $repository->shouldReceive('getCognitoUser')
            ->with($user->cognito_uuid)
            ->andReturn(null);

        $guard = new CognitoGuard($repository, $request);

        $result = $guard->user();
        $this->assertNull($result);
        $this->assertFalse($guard->hasUser());
        $this->assertFalse($guard->check());
    }

    /**
     * @test
     */
    public function testValidateThrowsAnException(){
        $guard = $this->app->make(CognitoGuard::class);

        $this->expectException(MethodNotSupportedException ::class);
        $this->expectExceptionMessage('CognitoGuard does not support the validate method.');
        $guard->validate();
    }

    /**
     * @test
     */
    public function testAttemptThrowsAnException(){
        $guard = $this->app->make(CognitoGuard::class);

        $this->expectException(MethodNotSupportedException ::class);
        $this->expectExceptionMessage('CognitoGuard does not support the attempt method.');
        $guard->attempt();
    }
}
