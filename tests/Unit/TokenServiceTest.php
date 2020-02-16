<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\Exceptions\InvalidTokenException;
use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\TokenService;
use Illuminate\Http\Request;
use phpseclib\Crypt\RSA;


class TokenServiceTest extends TestCase
{


    public function testGetTokenFromRequestCookie(){
        $jwt     = 'jwt';
        $sub     = 'sub';
        $request = $this->mock(Request::class);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '_' . $sub . '_accessToken';

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

        $request->shouldReceive('cookie')
            ->with($lastAuthUserKey)
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($accessTokenKey)
            ->andReturn(null);

        $request->shouldReceive('bearerToken')
            ->andReturn($jwt);

        $ts = new TokenService();
        $result = $ts->getTokenFromRequest($request);
        $this->assertEquals($jwt, $result);
    }

    public function testGetTokenFromRequestNull(){
        $request = $this->mock(Request::class);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '__' . 'accessToken';

        $request->shouldReceive('cookie')
            ->with($lastAuthUserKey)
            ->andReturn(null);

        $request->shouldReceive('cookie')
            ->with($accessTokenKey)
            ->andReturn(null);

        $request->shouldReceive('bearerToken')
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
            $mock->shouldReceive('getPemFromKid')
                ->with($jtb['kid'])
                ->andReturn($jtb['pem']);
        });

        $ts = new TokenService();

        $result = $ts->getCognitoUuidFromToken($jtb['jwt']);
        $this->assertEquals($jtb['sub'], $result);
    }

    /**
     * @test
     */
    public function testDecode()
    {
        $jtb = $this->getJwtTestBundle();
        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $mock->shouldReceive('getPemFromKid')
                ->with($jtb['kid'])
                ->andReturn($jtb['pem']);
        });

        $ts = new TokenService();

        $result = $ts->decode($jtb['jwt']);

        $this->assertEquals($jtb['sub'], $result->sub);
        $this->assertEquals($jtb['sub'], $result->username);
    }

    /**
     * @test
     */
    public function testDecodeWrongKey()
    {
        $jtb = $this->getJwtTestBundle();

        $this->mock(JwksService::class,  function ($mock) use($jtb) {
            $rsa = new RSA();
            $wrongKeypair = $rsa->createKey(512);

            $mock->shouldReceive('getPemFromKid')
                ->with($jtb['kid'])
                ->andReturn($wrongKeypair['publickey']);
        });

        $this->expectException(InvalidTokenException ::class);
        $ts = new TokenService();
        $ts->decode($jtb['jwt']);
    }

    /**
     * @test
     */
    public function testGetKid()
    {
        $jtb = $this->getJwtTestBundle();
        $ts  = $this->app->make(TokenService::class);
        $result = $ts->getKid($jtb['jwt']);

        $this->assertEquals($jtb['kid'], $result);
    }
}
