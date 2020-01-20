<?php
namespace BenBjurstrom\CognitoGuard\Tests\Unit;

use BenBjurstrom\CognitoGuard\JwksService;
use BenBjurstrom\CognitoGuard\Tests\TestCase;
use Illuminate\Support\Facades\Cache;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;


class JwksServiceTest extends TestCase
{

    /**
     * @test
     */
    public function testGetPemFromKid()
    {
        $jtb = $this->getJwtTestBundle();

        // called in getJwks
        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:jwks', 3600, \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn(json_encode($jtb['jwks']));

        // called in updatePemCache
        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:pem:' . $jtb['kid'], 3600, \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn(json_encode($jtb['pem']));

        // called in getPemFromKid
        Cache::shouldReceive('get')
            ->once()
            ->with('cognito:pem:' . $jtb['kid'], \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn($jtb['pem']);

        $js = new JwksService();
        $result = $js->getPemFromKid($jtb['kid']);

        $this->assertEquals($result, $jtb['pem']);
    }

    /**
     * @test
     */
    public function testUpdatePemCache()
    {
        $jtb    = $this->getJwtTestBundle();
        $js     = new JwksService();

        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:jwks', 3600, \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn(json_encode($jtb['jwks']));

        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:pem:' . $jtb['kid'], 3600, \Mockery::on(function($value){
                return is_callable($value);
            }));

        $js->updatePemCache($jtb['jwks']);
    }

    /**
     * @test
     */
    public function testJwkToPem()
    {
        $jtb = $this->getJwtTestBundle();

        $js = new JwksService();
        $result = $js->jwkToPem(json_decode(json_encode($jtb['jwk'])));

        $this->assertEquals($jtb['pem'], $result);
    }

    /**
     * @test
     */
    public function testGetJwks()
    {
        $jtb    = $this->getJwtTestBundle();
        $js     = new JwksService();

        Cache::shouldReceive('remember')
            ->once()
            ->with('cognito:jwks', 3600, \Mockery::on(function($value){
                return is_callable($value);
            }))
            ->andReturn(json_encode($jtb['jwks']));

        $result = $js->getJwks();
        $this->assertEquals(json_decode(json_encode($jtb['jwks'])), $result);
    }

    /**
     * @test
     */
    public function testDownloadJwks()
    {
        $jtb    = $this->getJwtTestBundle();
        $client = $this->getMockClient($jtb['jwks']);
        $js = new JwksService($client);
        $result = $js->downloadJwks();

        $this->assertEquals(json_encode($jtb['jwks']), $result);
    }

    /**
     * @return string
     */
    protected function getJwksJson(){
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
     * @param array $jwks
     * @return \Mockery\MockInterface
     */
    protected function getMockClient(array $jwks){
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');
        $url        = sprintf('https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);
        $client     = $this->mock(Client::class);

        $client->shouldReceive('get')
            ->with($url)
            ->andReturn(new Response(200, [], json_encode($jwks)));

        return $client;
    }
}
