<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\Exceptions\InvalidTokenException;
use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\TokenService;
use phpseclib\Crypt\RSA;


class TokenServiceTest extends TestCase
{

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
