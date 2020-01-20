<?php

namespace BenBjurstrom\CognitoGuard\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $casts = [
        'cognito_uuid' => 'string'
    ];
}
