<?php

namespace BenBjurstrom\CognitoGuard;

use GuzzleHttp\Client;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class CognitoServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ], 'config');

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
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
            return $guard;
        });
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cognito.php', 'cognito');
    }
}
