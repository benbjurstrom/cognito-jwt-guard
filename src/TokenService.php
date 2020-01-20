<?php

namespace BenBjurstrom\CognitoGuard;
use Firebase\JWT\JWT;
use Exception;
use BenBjurstrom\CognitoGuard\Exceptions\TokenVerificationException;

class TokenService
{
    /**
     * @param string $jwt
     * @return string
     * @throws \Throwable
     */
    public function getCognitoUuidFromToken(string $jwt){
        $payload = $this->decode($jwt);
        $this->validatePayload($payload);

        $cognitoUuid = $payload->username ?? $payload->{'cognito:username'};
        throw_unless($cognitoUuid, new Exception ('CognitoUuid not found'));

        return $cognitoUuid;
    }

    /**
     * JWT::decode will throw an exception if the token is expired or
     * otherwise invalid
     *
     * @param string $jwt
     * @return mixed
     * @throws \Throwable
     */
    public function decode(string $jwt){
        $kid = $this->getKid($jwt);
        $jwksService = app()->make(JwksService::class);
        $pem = $jwksService->getPemFromKid($kid);

        return JWT::decode($jwt, $pem, array('RS256'));
    }

    /**
     * Although we already know the token has a valid signature and is
     * unexpired, this method is used to validate the payload parameters.
     *
     * @param object $payload
     * @return mixed
     * @throws \Throwable
     */
    public function validatePayload(object $payload){
        $region     = config('cognito.user_pool_region');
        $poolId     = config('cognito.user_pool_id');
        $issuer = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $region, $poolId);
        throw_unless($payload->iss === $issuer, new TokenVerificationException ('Invalid issuer. Expected:'. $issuer));
        throw_unless(in_array($payload->token_use, ['id','access']), new TokenVerificationException ('Invalid token use'));
    }

    /**
     * @param string $jwt
     * @return string|null
     * @throws \Throwable
     */
    public function getKid(string $jwt): ?string
    {
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode(strtok($jwt, '.')));

        throw_unless(isset($header->kid), new TokenVerificationException('No kid present in token header'));
        throw_unless(isset($header->alg), new TokenVerificationException ('No alg present in token header'));
        throw_unless($header->alg === 'RS256', new TokenVerificationException ('The token alg  is not RS256'));

        return $header->kid;
    }
}
