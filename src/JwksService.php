<?php

namespace BenBjurstrom\CognitoGuard;

use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * A class for downloading and caching the Cognito JWKS for the given user pool and
 * region.
 *
 * @package BenBjurstrom\CognitoGuard
 */
class JwksService
{
    /**
     * @param string $region
     * @param string $poolId
     * @return array
     */
    public function getJwks(string $region, string $poolId): array
    {
        $json = Cache::remember('cognito:jwks-' . $poolId, 3600, function () use($region, $poolId) {
            return $this->downloadJwks($region, $poolId);
        });

        $keys = json_decode($json, true);
        return JWK::parseKeySet($keys);
    }

    /**
     * Download the jwks for the configured user pool
     *
     * @param string $region
     * @param string $poolId
     * @return string
     */
    public function downloadJwks(string $region, string $poolId): string
    {
        $url      = sprintf('https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json', $region, $poolId);
        $response = Http::get($url);
        $response->throw();

        return $response->body();
    }
}
