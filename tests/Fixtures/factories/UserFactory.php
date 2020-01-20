<?php

use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use Illuminate\Support\Str;
use Faker\Generator as Faker;
use Ramsey\Uuid\Uuid;

/*
|--------------------------------------------------------------------------
| Model Factories
|--------------------------------------------------------------------------
|
| This directory should contain each of the model factory definitions for
| your application. Factories provide a convenient way to generate new
| model instances for testing / seeding your application's database.
|
*/

$factory->define(User::class, function (Faker $faker) {
    return [
        'name' => $faker->name,
        'email' => $faker->unique()->safeEmail,
        'cognito_uuid' => Uuid::uuid4()
    ];
});
