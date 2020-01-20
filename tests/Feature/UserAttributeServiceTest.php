<?php
namespace BenBjurstrom\CognitoGuard\Tests\Feature;

use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\UserAttributeService;

class UserAttributeServiceTest extends TestCase
{
    public function testGetUserAttributes()
    {
        $uas = new UserAttributeService();
        $result = $uas->getUserAttributesFromToken(env('AWS_COGNITO_TEST_TOKEN'), config('cognito.user_pool_region'));
        dump($result);
        $this->assertArrayHasKey('sub', $result);
    }
}
