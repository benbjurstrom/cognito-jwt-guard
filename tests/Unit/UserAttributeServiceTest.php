<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\UserAttributeService;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;


class UserAttributeServiceTest extends TestCase
{
    /**
     * @test
     */
    public function testGetUserAttributes()
    {
        $token = 'SOME_TOKEN';
        $client = $this->getMockClient($token);
        $uas = new UserAttributeService($client);
        $result = $uas->getUserAttributesFromToken($token);

        $this->assertEquals($result, collect([
            'name' => 'Some Name',
            'email' => 'email@example.com',
        ]));
    }

    /**
     * @test
     */
    public function testConvertAttributesToArray()
    {
        $uas = new UserAttributeService();
        $result = $uas->collectAttributes($this->getUserAttributesJson());

        $this->assertEquals($result, collect([
            'name' => 'Some Name',
            'email' => 'email@example.com',
        ]));
    }

    /**
     * @test
     */
    public function testDownloadUserAttributes()
    {
        $token = 'SOME_TOKEN';
        $client = $this->getMockClient($token);
        $uas = new UserAttributeService($client);
        $result = $uas->downloadUserAttributes($token);

        $this->assertEquals($result, $this->getUserAttributesJson());
    }

    /**
     * @return string
     */
    protected function getUserAttributesJson(){
        return json_encode([
            'UserAttributes' => [
                [
                    'Name' => 'name',
                    'Value' => 'Some Name'
                ],
                [
                    'Name' => 'email',
                    'Value' => 'email@example.com'
                ],
            ]
        ]);
    }

    /**
     * @param string $token
     * @return \Mockery\MockInterface
     */
    protected function getMockClient($token){
        $region = config('cognito.user_pool_region');
        $url    = sprintf('https://cognito-idp.%s.amazonaws.com', $region);
        $client = $this->mock(Client::class);
        $client->shouldReceive('request')
            ->with('POST', $url, [
                'headers' => [
                    'Content-Type' => 'application/x-amz-json-1.1',
                    'X-Amz-Target' => 'AWSCognitoIdentityProviderService.GetUser',
                    'Content-Length' => '1162'
                ],
                'body' => json_encode(['AccessToken' => $token])
            ])
            ->andReturn(new Response(200, [], $this->getUserAttributesJson()));

        return $client;
    }
}
