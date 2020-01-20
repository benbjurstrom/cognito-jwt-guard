<?php

namespace BenBjurstrom\CognitoGuard;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use pmill\AwsCognito\Exception\TokenInvalidKidException;

/**
 * A class for downloading the Cognito JWKS for the configured user pool and
 * region, converting each JWK into a PEM, and caching each PEM by KID.
 *
 * @package BenBjurstrom\CognitoGuard
 */
class JwksService
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * JwksService constructor.
     * @param Client $client
     */
    public function __construct(Client $client = null)
    {
        if(!$client){
            $client = new Client;
        }

        $this->client = $client;
    }

    /**
     * @param string $kid
     * @return string
     * @throws
     */
    public function getPemFromKid(string $kid): string
    {
        $this->updatePemCache();
        return Cache::get('cognito:pem:' . $kid, function () {
            throw new TokenInvalidKidException('The given userpool does not have a jwk matching the kid provided. If you believe this message is in error try clearing your cache.');
        });
    }

    /**
     *
     */
    public function updatePemCache(){
        foreach($this->getJwks()->keys as $key){
            $pem = Cache::remember('cognito:pem:' . $key->kid, 3600, function () use ($key) {
                return $this->jwkToPem($key);
            });
        }
    }

    /**
     * @param object $jwk
     * @return string
     * @throws \Throwable
     */
    public function jwkToPem(object $jwk): string
    {
        throw_unless(
            isset($jwk->e)
            && isset($jwk->n)
            && $jwk->kty === 'RSA' // RSA key type is currently only supported
            && empty($jwk->d), // Public key is currently only supported.
            new \Exception('Invalid jwk given')
        );

        $rsa = new RSA();
        $rsa->loadKey([
            'e' => new BigInteger(JWT::urlsafeB64Decode($jwk->e), 256),
            'n' => new BigInteger(JWT::urlsafeB64Decode($jwk->n),  256)
        ]);

        return $rsa->getPublicKey();
    }

    /**
     * @return string
     */
    public function getJwks()
    {
        $json = Cache::remember('cognito:jwks', 3600, function () {
            return $this->downloadJwks();
        });

        return json_decode($json);
    }

    /**
     * Download the jwks for the configured user pool
     *
     * @param  Client $client
     * @return mixed
     */
    public function downloadJwks(){
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');
        $url        = sprintf('https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);

        $response   = $this->client->get($url);
        return strval($response->getBody());
    }
}
