<?php
namespace BenBjurstrom\CognitoGuard\Tests\Feature;

use BenBjurstrom\CognitoGuard\Tests\TestCase;
use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use BenBjurstrom\CognitoGuard\CognitoClient;

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
        $user = factory(User::class)->create();
        $user->cognito_uuid = $this->cognito_uuid;
        $user->save();

        config()->set('cognito.use_sso', false);
        $this->withHeader('Authorization', 'Bearer ' . $this->token);
        $this->getJson('/user')->dump()
            ->assertSuccessful();
    }

    /**
     * @test
     */
    public function testGuardCreatesSsoUser()
    {
        $this->assertDatabaseMissing('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);

        config()->set('cognito.use_sso', true);
        $this->withHeader('Authorization', 'Bearer ' . $this->token);
        $this->getJson('/user')->dump()
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
        $this->getJson('/user')->dump()
            ->assertStatus(401);
    }

    /**
     * @test
     */
    public function testGuardWithInvalidToken()
    {
        $this->assertDatabaseMissing('users', [
            'cognito_uuid' => $this->cognito_uuid
        ]);

        $this->withHeader('Authorization', 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlZUcGRrMldReWtUYVBONFFXa2NQTFN5UGxCaHd6V0g4UkRRbTVKUjVKbkE9In0.eyJzdWIiOiIwZDBjZDI2ZS1lZDE0LTRjYTctYjczYy03NTE1NjFjOTY0YTIiLCJkZXZpY2Vfa2V5IjoidXMtd2VzdC0yXzNkMmM3Nzk5LTVjOGUtNDk4NC1hYTliLWIzMmQ2ZTI1OTY5YiIsImV2ZW50X2lkIjoiZTMwYTQ2ZmYtMjMxZS00NWNiLTg3NzItN2U1YTViYzQxZDY3IiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU3OTU1NTk5NSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6b25hd3MuY29tXC91cy13ZXN0LTJfdVgyWlRlSFJCIiwiZXhwIjoxNTc5NTU5NTk1LCJpYXQiOjE1Nzk1NTU5OTUsImp0aSI6IjI3ZGIyOWNkLWExMGMtNDRmOS1iODNmLTMwY2FkZWZiYTg1YyIsImNsaWVudF9pZCI6IjRhNjU4MmU3YTY0NmEzOGQ3NmJkOGFkNmE4IiwidXNlcm5hbWUiOiIwZDBjZDI2ZS1lZDE0LTRjYTctYjczYy03NTE1NjFjOTY0YTIifQ.Lx3cAF-v-cFn4BQkUD1i0aPafkpyeKzwT8AdosH22IWkrVIM8MvU642UEpm743vq8pD_ofWDYwcD2L967Z3yWA');
        $this->getJson('/user')
            ->assertStatus(401);
    }
}
