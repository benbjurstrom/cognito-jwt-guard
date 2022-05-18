<?php
namespace Alsbury\CognitoGuard\Tests\Unit;

use Alsbury\CognitoGuard\Exceptions\InvalidTokenException;
use Alsbury\CognitoGuard\JwksService;
use Alsbury\CognitoGuard\Tests\TestCase;
use Alsbury\CognitoGuard\TokenService;
use Firebase\JWT\JWK;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class JwksServiceTest extends TestCase
{

    /**
     * @test
     */
    public function testGetJwks()
    {
        $jtb    = $this->getJwtTestBundle();
        $js     = new JwksService();

        $region = 'SOME_REGION';
        $poolId = 'SOME_POOL_ID';

        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:jwks-' . $poolId, 3600, \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn(json_encode($jtb->jwks));

        $result = $js->getJwks($region, $poolId);
        $this->assertEquals(JWK::parseKeySet($jtb->jwks), $result);
    }

    /**
     * @test
     */
    public function testGetJwksCacheMiss()
    {
        $jtb    = $this->getJwtTestBundle();
        $js     = new JwksService();

        $region = 'some_region';
        $poolId = 'some_pool_id';
        $url    = sprintf('cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);

        Http::fake([
            $url => Http::response($jtb->jwks, 200),
        ]);

        $result = $js->getJwks($region, $poolId);
        $this->assertEquals(JWK::parseKeySet($jtb->jwks), $result);
    }

    /**
     * @test
     */
    public function testDownloadJwks()
    {
        $jtb    = $this->getJwtTestBundle();

        $region = 'some_region';
        $poolId = 'some_pool_id';
        $url    = sprintf('cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);

        Http::fake([
            $url => Http::response($jtb->jwks, 200),
        ]);

        $js = $this->app->make(JwksService::class);
        $result = $js->downloadJwks($region, $poolId);

        $this->assertEquals(json_encode($jtb->jwks), $result);
    }

    /**
     * @test
     */
    public function testDownloadJwksThrowsExceptionOn404()
    {
        $region = 'some_region';
        $poolId = 'us-west-2_123';
        $url    = sprintf('cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);

        Http::fake([
            $url => Http::response(['message' => 'User pool us-west-2_123 does not exist.'], 404),
        ]);

        $js = $this->app->make(JwksService::class);
        $this->expectException(RequestException ::class);
        $this->expectExceptionMessage('User pool us-west-2_123 does not exist.');
        $result = $js->downloadJwks($region, $poolId);
    }
}
