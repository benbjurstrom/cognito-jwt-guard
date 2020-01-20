<?php

namespace BenBjurstrom\CognitoGuard;

use DemeterChain\C;
use GuzzleHttp\Client;
use Illuminate\Foundation\Application;
use Illuminate\Support\Collection;
use Illuminate\Support\ServiceProvider;

/**
 * A class for downloading Cognito User Attributes that belong to the owner
 * of the given jwt and converting them into a [key => value] format.
 *
 * @package BenBjurstrom\CognitoGuard
 */
class UserAttributeService
{

    /**
     * @var Client
     */
    protected $client;

    /**
     * UserAttributeService constructor.
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
     * @param $token
     * @param $region
     * @return Collection
     */
    public function getUserAttributesFromToken($token)
    {
        $json = $this->downloadUserAttributes($token);
        return $this->collectAttributes($json);
    }

    /**
     * Get user attributes in [key => value] format
     *
     * @param  string $json
     * @return Collection
     */
    public function collectAttributes($json)
    {
        $array = json_decode($json, true);
        return collect($array['UserAttributes'])->mapWithKeys(function ($item) {
            return [$item['Name'] => $item['Value']];
        });
    }

    /**
     * Download the Cognito UserAttributes that belong to the given token
     *
     * @param  string $token
     * @return string
     */
    public function downloadUserAttributes($token){

        $region     = config('cognito.user_pool_region');
        $url = sprintf('https://cognito-idp.%s.amazonaws.com', $region);
        $response = $this->client->request('POST', $url, [
            'headers' => [
                'Content-Type' => 'application/x-amz-json-1.1',
                'X-Amz-Target' => 'AWSCognitoIdentityProviderService.GetUser',
                'Content-Length' => '1162' // Access Token bytes length
            ],
            'body' => json_encode(['AccessToken' => $token])
        ]);

        return strval($response->getBody());
    }
}
