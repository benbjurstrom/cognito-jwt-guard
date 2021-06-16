<?php

namespace BenBjurstrom\CognitoGuard\Tests\Fixtures;

use BenBjurstrom\CognitoGuard\Tests\Fixtures\Factories\UserFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasFactory;

    protected static function newFactory()
    {
        return UserFactory::new();
    }

    protected $casts = [
        'cognito_uuid' => 'string'
    ];

    public function createCognitoUser(User $user): User
    {
        $user->name = 'Another Body';
        $user->save();

        return $user;
    }

}
