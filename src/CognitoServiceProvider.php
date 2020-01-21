<?php

namespace BenBjurstrom\CognitoGuard;

use GuzzleHttp\Client;
use Illuminate\Support\Collection;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class CognitoServiceProvider extends ServiceProvider
{
    public function boot(Filesystem $filesystem)
    {
        $this->publishes([
            __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ], 'config');

        $this->publishes([
            __DIR__.'/../database/migrations/alter_users_table.php.stub' => $this->getMigrationFileName($filesystem),
        ], 'migrations');

        $this->app->singleton(JwksService::class, function (Application $app) {
            return new JwksService( new Client);
        });

        $this->app->singleton(TokenService::class, function (Application $app) {
            return new TokenService();
        });

        $this->app->singleton(CognitoGuard::class, function (Application $app) {
            return new CognitoGuard(
                $app['request'],
                new ProviderRepository($app['auth']->createUserProvider('users'))
            );
        });

        $this->app['auth']->extend('cognito', function ($app, $name, array $config) {
            $guard = $app->make(CognitoGuard::class);
            return $guard;
        });
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cognito.php', 'cognito');
    }

    /**
     * Returns existing migration file if found, else uses the current timestamp.
     *
     * @param Filesystem $filesystem
     * @return string
     */
    protected function getMigrationFileName(Filesystem $filesystem): string
    {
        $timestamp = date('Y_m_d_His');

        return Collection::make($this->app->databasePath().DIRECTORY_SEPARATOR.'migrations'.DIRECTORY_SEPARATOR)
            ->flatMap(function ($path) use ($filesystem) {
                return $filesystem->glob($path.'*_create_permission_tables.php');
            })->push($this->app->databasePath()."/migrations/{$timestamp}_create_permission_tables.php")
            ->first();
    }
}
