<?php
namespace Alsbury\CognitoGuard\Tests\Feature;

use Alsbury\CognitoGuard\Exceptions\InvalidTokenException;
use Alsbury\CognitoGuard\Tests\TestCase;
use Alsbury\CognitoGuard\Tests\Fixtures\User;
use Alsbury\CognitoGuard\CognitoClient;
use Alsbury\CognitoGuard\TokenService;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Validation\ValidationException;

class CognitoGuardTest extends TestCase
{
    /**
     * @var string
     */
    protected $token;
    /**
     * @var string
     */
    protected $cognito_uuid;

    /**
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();
        $this->token = env('AWS_COGNITO_TEST_TOKEN', 'token');
        $this->cognito_uuid = env('AWS_COGNITO_TEST_USERNAME', 'token');
    }

    /**
     * @test
     */
    public function testGuardWithExistingUser()
    {
        $user = User::factory()->create();
        $user->cognito_uuid = $this->cognito_uuid;
        $user->save();

        $this->withHeader('Authorization', 'Bearer ' . $this->token);
        $result = $this->getJson('/user')
            ->assertSuccessful();

        $result->assertJsonFragment(['cognito_uuid' => $user->cognito_uuid]);
    }

    /**
     * @test
     */
    public function testGuardWithInvalidToken()
    {
        $user = User::factory()->create();
        $user->cognito_uuid = $this->cognito_uuid;
        $user->save();

        $this->withHeader('Authorization', 'Bearer INVALID_TOKEN');
        $this->getJson('/user')->dump()->assertUnauthorized();
    }

    /**
     * @test
     */
    public function testGuardCreatesSsoUserFromCookie()
    {
        $this->assertDatabaseMissing('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);

        config()->set('cognito.sso', true);

        $this->withHeaders([
            'CONTENT_TYPE' => 'application/json',
            'Accept' => 'application/json',
        ]);

        $prefix = 'CognitoIdentityServiceProvider_' . config('cognito.user_pool_client_id');
        $lastAuthUserKey = $prefix . '_LastAuthUser';
        $accessTokenKey = $prefix . '_' . $this->cognito_uuid . '_accessToken';

        $this->withUnencryptedCookies([
            $lastAuthUserKey => $this->cognito_uuid,
            $accessTokenKey => $this->token
        ])->get('/user')
            ->assertSuccessful();

        $this->assertDatabaseHas('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);
    }

    /**
     * @test
     */
    public function testGuardCreatesSsoUserBearerToken()
    {
        $this->assertDatabaseMissing('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);

        config()->set('cognito.sso', true);
        $this->withHeader('Authorization', 'Bearer ' . $this->token);
        $this->getJson('/user')
            ->assertSuccessful();

        $this->assertDatabaseHas('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);
    }

    /**
     * @test
     */
    public function testGuardWithExpiredToken()
    {
        $this->assertDatabaseMissing('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);

        $this->withHeader('Authorization', 'Bearer eyJraWQiOiJwcFZ6SXVNVzBHVVZvUTBOZldPdE1lc0t5OHRucSt5K1N3ZjF4dVN5c3BBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyNDZkYjdkMC02MzdhLTRhODQtYWE3ZC04MGMwODJiODI4NDkiLCJkZXZpY2Vfa2V5IjoidXMtd2VzdC0yX2RlNjdlZDViLTE1MzUtNGQyNC1hNTRlLTE1ZGNiNDBlNTg4YiIsImV2ZW50X2lkIjoiNzBlNWNmOTYtOGM1ZS00MzdhLWFiNmUtYjJiMjhkZWMyYmE4IiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU3OTUwODM2NCwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6b25hd3MuY29tXC91cy13ZXN0LTJfdVgyWlRlSFJCIiwiZXhwIjoxNTc5NTExOTY0LCJpYXQiOjE1Nzk1MDgzNjQsImp0aSI6IjhhZGZlZGQxLTcxNTQtNDVjNS04ZTlkLWQ3ZmE0OTk0MmVhMSIsImNsaWVudF9pZCI6IjJsMzk1OGE0am9pdjFjdnNwa2o2aWFvYWRzIiwidXNlcm5hbWUiOiIyNDZkYjdkMC02MzdhLTRhODQtYWE3ZC04MGMwODJiODI4NDkifQ.ArOTBhJ91bwebU7zr-dt6-8TruI4oDxVAP0Nx6yUpWgHaOFvREiTTkHhHldxW0_hU-UT47hUxGK6otHqRF1t4vSJf8-HIMesGB_zluHyB--KY58EMm8uywtV2lUpr5ZVXZ1sKJYtJfNFGxchnK9wfPLmTmt673aRjFEWqNwW7IICOrTb2SzjKcNMGPfbn-n2j_Bj-DKsWCxsHDCeFdHyQEfIcJD7LalFbfluFjEK1y8P61ojGPaYFo2291mZBfHA85KY0YZCuAYw1Yn0LDlRE95c9wQ29TxqFx7VtUF4LznapZlFZHdM8M3tk5JKD5ZsUHObr-DENNRDuLFTgD648Q');
        $this->getJson('/user')
            ->assertStatus(401);
    }


    /**
     * Ensures that all required attributes specified in the config were
     * returned from cognito.
     *
     * @param Collection $attributes
     * @param Collection $requiredKeys
     * @throws \Throwable
     */
    protected function validateAttributes(Collection $attributes, Collection $requiredKeys)
    {

        throw_unless($diff->isEmpty(), new MissingRequiredAttributesException('Required attributes (' . $diff->implode(',') . ') were not returned by cognito'));
    }
}
