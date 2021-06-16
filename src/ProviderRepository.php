<?php

namespace BenBjurstrom\CognitoGuard;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;


/**
 * Class ProviderRepository
 * @package BenBjurstrom\CognitoGuard
 */
class ProviderRepository
{
    /**
     * @var EloquentUserProvider
     */
    protected $provider;

    /**
     * ProviderRepository constructor.
     * @param EloquentUserProvider $provider
     */
    public function __construct(EloquentUserProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * @param string $cognitoUuid
     * @return Authenticatable | null
     */
    public function getCognitoUser(string $cognitoUuid): ?Authenticatable
    {
        $model = $this->provider->createModel();
        $user = $model->where(config('cognito.cognito_uuid_key'), $cognitoUuid)->first();

        if ($user) {
            return $user;
        }

        return null;
    }
}
