<?php
namespace BenBjurstrom\CognitoGuard\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use BenBjurstrom\CognitoGuard\CognitoServiceProvider;
use Ramsey\Uuid\Uuid;
use phpseclib\Crypt\RSA;
use Firebase\JWT\JWT;
use Jose\Component\KeyManagement\JWKFactory;

abstract class TestCase extends Orchestra
{
    use DatabaseTransactions;

    public function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/Fixtures'));
        $this->artisan('migrate');

        $this->withFactories(realpath(__DIR__.'/Fixtures/factories'));

        \Route::get('auth-required', function () {
            return auth()->user();
        })->middleware(SubstituteBindings::class)->middleware('auth');
    }

    protected function getPackageProviders($app)
    {
        return [CognitoServiceProvider::class];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.guards.api.driver', 'cognito');
        $app['config']->set('auth.providers.users.model', User::class);
    }

    /**
     * Provides an array containing a jwks with a single jwk, the jwk in pem
     * format, a jwt signed with the pem, and the kid of the jwt.
     *
     * @throws
     * @return array
     */
    protected function getJwtTestBundle()
    {
        $sub = Uuid::uuid4()->toString();
        $now =  time();

        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');
        $issuer = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $region, $poolId);

        $payload = [
            'sub' => $sub,
            'device_key' => 'us-west-2_' .  Uuid::uuid4(),
            'event_id' => Uuid::uuid4(),
            'token_use' => 'access',
            'scope' => 'aws.cognito.signin.user.admin',
            'auth_time' => $now,
            'iss' => $issuer,
            'exp' => $now+3600,
            'iat' => $now,
            'jti' => Uuid::uuid4()->toString(),
            'client_id' => bin2hex(random_bytes(13)),
            'username' => $sub
        ];

        $rsa = new RSA();
        $keypair = $rsa->createKey(512);

        $kid = (base64_encode(hash ( 'sha256' , $keypair['publickey'], true)));
        $jwt = JWT::encode($payload, $keypair['privatekey'], 'RS256', $kid);
        $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($keypair['publickey']));
        $jwk = [
            'kty' => 'RSA',
            'kid' => $kid,
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['n'])), '='),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['e'])), '='),
        ];
        $jwks =  [ 'keys' => [$jwk]];

        return [
            'jwt'  => $jwt,
            'kid'  => $kid,
            'jwk'  => $jwk,
            'jwks' => $jwks,
            'pem'  => $keypair['publickey'],
            'sub'  => $sub,
        ];
    }
}
