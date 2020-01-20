<?php

namespace BenBjurstrom\CognitoGuard;

use BenBjurstrom\CognitoGuard\Exceptions\MissingRequiredAttributesException;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;


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
     * @param string $jwt
     * @return Authenticatable | null
     */
    public function getCognitoUser(string $cognitoUuid, $jwt) {
        $model = $this->provider->createModel();
        $user = $model->where('cognito_uuid', $cognitoUuid)->first();

        if ($user) {
            return $user;
        }

        return $this->createSsoUser($cognitoUuid, $jwt);
    }


    /**
     * @param string $cognitoUuid
     * @param string $jwt
     * @return Authenticatable | null
     * @throws
     */
    public function createSsoUser($cognitoUuid, $jwt)
    {
        if(!config('cognito.use_sso')){
            return null;
        };

        $attributes = $this->getAttributes($jwt);
        $requiredKeys = collect(config('cognito.sso_user_attributes'));

        $user = $this->provider->createModel();
        $user->cognito_uuid = $cognitoUuid;
        foreach($requiredKeys as $requiredKey){
            $user->$requiredKey = $attributes[$requiredKey];
        }

        $user->save();

        return $user;
    }

    /**
     * @param $jwt
     * @return mixed
     * @throws
     */
    public function getAttributes($jwt){
        $uas = app()->make(UserAttributeService::class);

        $attributes = $uas->getUserAttributesFromToken($jwt);
        $requiredKeys = collect(config('cognito.sso_user_attributes'));

        $this->validateAttributes($attributes, $requiredKeys);

        return $attributes;
    }

    /**
     * Ensures that all required attributes specified in the config were
     * returned from cognito.
     *
     * @param Collection $attributes
     * @param array $requiredKeys
     * @throws
     */
    public function validateAttributes(Collection $attributes, Collection $requiredKeys)
    {
        $diff = $requiredKeys->diff($attributes->keys());
        throw_unless($diff->isEmpty(), new MissingRequiredAttributesException('Required attributes (' . $diff->implode(',') . ') were not returned by cognito'));
    }
}
