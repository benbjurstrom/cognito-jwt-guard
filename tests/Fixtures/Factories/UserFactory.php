<?php

namespace BenBjurstrom\CognitoGuard\Tests\Fixtures\Factories;

use BenBjurstrom\CognitoGuard\Tests\Fixtures\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Ramsey\Uuid\Uuid;

class UserFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = User::class;

    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        return [
            'name' => $this->faker->name(),
            'email' => $this->faker->unique()->safeEmail(),
            'cognito_uuid' => Uuid::uuid4(),
        ];
    }
}
