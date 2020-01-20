<?php
namespace BenBjurstrom\CognitoGuard\Tests\Feature;

use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\UserAttributeService;

class JwksServiceTest extends TestCase
{
    public function testGetUserAttributes()
    {
        $js = new JwksService();
        $result = json_decode($js->downloadJwks(), true);
        dump($result);
        $this->expectNotToPerformAssertions();
    }
}
