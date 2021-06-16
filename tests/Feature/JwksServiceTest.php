<?php
namespace BenBjurstrom\CognitoGuard\Tests\Feature;

use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\UserAttributeService;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JwksServiceTest extends TestCase
{
    public function testDownloadJwks()
    {
        $region = config('cognito.user_pool_region');
        $poolId = config('cognito.user_pool_id');

        $js = new JwksService();

        $result = json_decode($js->downloadJwks($region, $poolId), true);
        $parsed = JWK::parseKeySet($result);
        dump($parsed);
        $this->expectNotToPerformAssertions();
    }

    public function testGetJwks()
    {
        $region = config('cognito.user_pool_region');
        $poolId = config('cognito.user_pool_id');

        $js = new JwksService();
        $keys = $js->getJwks($region, $poolId);
        $jwt = env('AWS_COGNITO_TEST_TOKEN', 'token');
        $decoded = JWT::decode($jwt, $keys, ['RS256']);

        dump($decoded);
        $this->expectNotToPerformAssertions();
    }
}
