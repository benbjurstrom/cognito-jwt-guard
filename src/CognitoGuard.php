<?php

namespace BenBjurstrom\CognitoGuard;

use BenBjurstrom\CognitoGuard\Exceptions\MethodNotSupportedException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

class CognitoGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * @var ProviderRepository
     */
    protected $provider;

    /**
     * @param ProviderRepository $provider
     * @param Request  $request
     *
     * @return void
     */
    public function __construct(ProviderRepository $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request  = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @throws
     * @return Authenticatable|null
     */
    public function user(){
        if ($this->user  instanceof Authenticatable) {
            return $this->user;
        }

        $ts = app()->make(TokenService::class);
        $jwt = $ts->getTokenFromRequest($this->request);

        if(! $jwt){
            return null;
        }

        $cognitoUuid = $ts->getCognitoUuidFromToken($jwt);

        return $this->user = $this->provider->getCognitoUser($cognitoUuid);
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function validate(array $credentials = []){
        throw new MethodNotSupportedException('CognitoGuard does not support the validate method.');
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function attempt(array $credentials = [])
    {
        throw new MethodNotSupportedException('CognitoGuard does not support the attempt method.');
    }
}
