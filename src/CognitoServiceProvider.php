<?php

namespace BenBjurstrom\CognitoGuard;

use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class CognitoServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/cognito.php' => config_path('cognito.php'),
            ], 'config');
        }

        $this->app->singleton(JwksService::class, function (Application $app) {
            return new JwksService();
        });

        $this->app->singleton(TokenService::class, function (Application $app) {
            return new TokenService();
        });

        $this->app->singleton(CognitoGuard::class, function (Application $app) {
            return new CognitoGuard(
                new ProviderRepository($app['auth']->createUserProvider('users')),
                $app['request']
            );
        });

        $this->app['auth']->extend('cognito', function ($app, $name, array $config) {
            $guard = $app->make(CognitoGuard::class);
            return $guard;
        });
    }

    public function register()
    {
        if (! $this->app->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__.'/../config/cognito.php', 'cognito');
        }
    }
}
