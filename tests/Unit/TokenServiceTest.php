<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\Exceptions\InvalidTokenException;
use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\TokenService;
use DateTime;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use phpseclib3\Crypt\RSA;
use function date;


class TokenServiceTest extends TestCase
{

    public function testGetTokenFromRequestCookie(){
        $jwt     = 'jwt';
        $sub     = 'sub';
        $request = $this->mock(Request::class);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '_' . $sub . '_accessToken';

        $request->shouldReceive('bearerToken')
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($lastAuthUserKey)
            ->andReturn($sub);

        $request->shouldReceive('cookie')
            ->with($accessTokenKey)
            ->andReturn($jwt);

        $ts = new TokenService();
        $result = $ts->getTokenFromRequest($request);
        $this->assertEquals($jwt, $result);
    }

    public function testGetTokenFromRequestBearer(){
        $jwt     = 'jwt';
        $request = $this->mock(Request::class);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '__' . 'accessToken';

        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $request->shouldReceive('cookie')
            ->with($lastAuthUserKey)
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($accessTokenKey)
            ->andReturn(null);

        $ts = new TokenService();
        $result = $ts->getTokenFromRequest($request);
        $this->assertEquals($jwt, $result);
    }

    public function testGetTokenFromRequestNull(){
        $request = $this->mock(Request::class);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '__' . 'accessToken';

        $request->shouldReceive('bearerToken')
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($lastAuthUserKey)
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($accessTokenKey)
            ->andReturn(null);

        $ts = new TokenService();
        $result = $ts->getTokenFromRequest($request);
        $this->assertNull($result);
    }

    /**
     * @test
     */
    public function testGetCognitoUuidFromToken()
    {
        $jtb = $this->getJwtTestBundle();

        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        $ts = new TokenService();

        $result = $ts->getCognitoUuidFromToken($jtb->jwt);
        $this->assertEquals($jtb->sub, $result);
    }

    /**
     * @test
     */
    public function testDecode()
    {
        $jtb = $this->getJwtTestBundle();
        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        $ts = new TokenService();

        $result = $ts->decode($jtb->jwt);

        $this->assertEquals($jtb->sub, $result->sub);
        $this->assertEquals($jtb->sub, $result->username);
    }

    /**
     * @test
     */
    public function testDecodeFailsIfWrongKid()
    {
        $jtb = $this->getJwtTestBundle();

        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $wrongKeypair = RSA::createKey(512);

            $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($wrongKeypair->getPublicKey()));

            $wrong_jwk  = [
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['n'])), '='),
                        'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['e'])), '='),
                    ],
                ],
            ];

            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($wrong_jwk));
        });

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('"kid" invalid, unable to lookup correct key');
        $ts = new TokenService();
        $ts->decode($jtb->jwt);
    }

    /**
     * @test
     */
    public function testDecodeFailsIfInvalidToken()
    {
        $jtb = $this->getJwtTestBundle();
        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        // This JWT has correct payload and header but is signed with a different key.
        $keypair = RSA::createKey(512);
        $invalid_jwt = JWT::encode($jtb->payload, $keypair, 'RS256', $jtb->kid);

        $ts = new TokenService();

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Signature verification failed');
        $ts->decode($invalid_jwt);
    }

    /**
     * @test
     */
    public function testDecodeFailsIfExpiredToken()
    {
        $jtb = $this->getJwtTestBundle();
        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        // This JWT has correct payload and header but is signed with a different key.
        $payload = $jtb->payload;
        $payload->exp = time() - 1;
        $expired_jwt = JWT::encode($payload, $jtb->keypair, 'RS256', $jtb->kid);

        $ts = new TokenService();

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Expired token');
        $ts->decode($expired_jwt);
    }

    /**
     * @test
     */
    public function testDecodeFailsIfNbfToken()
    {
        $jtb = $this->getJwtTestBundle();
        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getJwks')
                ->andReturn(JWK::parseKeySet($jtb->jwks));
        });

        // This JWT has correct payload and header but is signed with a different key.
        $payload = $jtb->payload;
        $payload->iat = time() + 500;
        $expired_jwt = JWT::encode($payload, $jtb->keypair, 'RS256', $jtb->kid);

        $ts = new TokenService();

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat));
        $ts->decode($expired_jwt);
    }

    /**
     * @test
     */
    public function testValidateHeader()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);
        $ts->validateHeader($jtb->jwt);

        $this->expectNotToPerformAssertions();
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfWrongSegments()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Wrong number of segments');
        $ts->validateHeader('INVALID_TOKEN');
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfNotJson()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Syntax error, malformed JSON');
        $ts->validateHeader('IN.VALID.TOKEN');
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfNotB64()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Malformed UTF-8 characters');
        $ts->validateHeader(json_encode(['kid'=>'123']) . '.seg2.seg3');
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfNoAlg()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('No alg present in token header');
        $ts->validateHeader(base64_encode(json_encode(['kid'=>'123'])) . '.seg2.seg3');
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfAlgNotRS256()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('The token alg is not RS256');
        $ts->validateHeader(base64_encode(json_encode(['kid'=>'123', 'alg'=>'other'])) . '.seg2.seg3');
    }

    /**
     * @test
     */
    public function testValidateHeaderFailsIfNoKid()
    {
        $jtb = $this->getJwtTestBundle();
        $jwtNoKid = JWT::encode($jtb->payload, $jtb->keypair, 'RS256');
        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('No kid present in token header');
        $ts->validateHeader($jwtNoKid);
    }

    /**
     * @test
     */
    public function testValidatePayloadFailsIfIssuerDoesntMatch()
    {
        $jtb = $this->getJwtTestBundle();
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');

        $issuer = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $region, 'WRONG_ISSUER');
        $jtb->payload->iss = $issuer;

        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Invalid issuer');
        $ts->validatePayload((object) $jtb->payload, $region, $poolId);
    }

    /**
     * @test
     */
    public function testValidatePayloadFailsIfIncorrectTokenUse()
    {
        $jtb = $this->getJwtTestBundle();
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');

        $jtb->payload->token_use = 'WRONG_USE';

        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Invalid token_use');
        $ts->validatePayload((object) $jtb->payload, $region, $poolId);
    }

    /**
     * @test
     */
    public function testValidatePayloadFailsIfNoUsername()
    {
        $jtb = $this->getJwtTestBundle();
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');

        unset($jtb->payload->username);

        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Invalid token attributes. Token must include one of "username","cognito:username"');
        $ts->validatePayload((object) $jtb->payload, $region, $poolId);
    }

    /**
     * @test
     */
    public function testValidatePayloadFailsIfUsernameIsNotUuid()
    {
        $jtb = $this->getJwtTestBundle();
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');

        $jtb->payload->username = '123';

        $ts  = $this->app->make(TokenService::class);

        $this->expectException(InvalidTokenException ::class);
        $this->expectExceptionMessage('Invalid token attributes. Parameters "username" and "cognito:username" must be a UUID.');
        $ts->validatePayload((object) $jtb->payload, $region, $poolId);
    }
}
