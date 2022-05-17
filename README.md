# Cognito JWT Guard
Laravel authorization guard for JSON Web Tokens issued by Amazon AWS Cognito

This project is fork of [benbjurstrom/cognito-jwt-guard](https://github.com/benbjurstrom/cognito-jwt-guard) which appears to be abandoned.

## Overview
 This package provides a Laravel authentication guard to validate JSON Web Tokens (JWT) issued by the configured AWS Cognitio User Pool. The guard accepts tokens passed through the Authorization header or set as a CognitoIdentityServiceProvider cookie.
 
 Once the token has been validated against the pool’s public key the guard will look for a Laravel user with a cognito_uuid value equal to the username property contained in the token.  
 
 If a local Laravel user is found the guard will authenticate them for the duration of the request. If one is not found and Single Sign-On is enabled this package will create a new Laravel user.
 
 Note that this package does not provide methods for exchanging a username and password for a token. As such it is intended to be used with Laravel API-driven applications where the client would either obtain the token directly from Cognito or through a dedicated application responsible for authentication.
 
## Installation

You can install the package using composer

```shell script
composer require alsbury/cognito-jwt-guard
```

Next publish the [migration](https://github.com/alsbury/cognito-jwt-guard/blob/master/database/migrations/add_cognito_uuid_to_users_table.php.stub) and the [config/cognito.php](https://github.com/alsbury/cognito-jwt-guard/blob/master/config/cognito.php) config file with:

```shell script
 php artisan vendor:publish --provider="Alsbury\CognitoGuard\CognitoServiceProvider"
```

Next go ahead and run your migrations. This will add the required cognito_uuid property to your users table
```shell script
php artisan migrate
```

Add your AWS Cognito user pool's identifier and region to the `.env` file
```yaml
AWS_COGNITO_REGION=
AWS_COGNITO_USER_POOL_ID=
```

You will also need to change the auth driver in your config/auth.php file
```php
// config/auth.php
'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    'api' => [
        'driver' => 'cognito', // This line is important 
        'provider' => 'users',
    ],
],
```

Finally, depending on how you configured your Cognito User Pool's required attributes you may also want to make adjustments to your Single Sign-On settings in the published config/cognito.php file
```php
// config/cognito.php
/*
|--------------------------------------------------------------------------
| Single Sign-On Settings
|--------------------------------------------------------------------------
| If sso is true the cognito guard will automatically create a new user 
| record anytime the username attribute contained in a validated JWT 
| does not already exist in the users table.
|
| The new user will be created with the user attributes listed here
| using the values stored in the given cognito user pool. Each attribute
| listed here must be set as a required attribute in your cognito user
| pool.
|
| When sso_repository_class is set this package will pass a new instance
| of the the auth provider's user model to the given class's
| createCognitoUser method. The users model will be hydrated with the given
| sso_user_attributes before it is passed.
*/

'sso'                   => env('SSO', false),
'sso_repository_class'  => null,
'sso_user_attributes'   => [
    'name',
    'email',
    ]
```

Configuring an sso_repository_class is optional but doing so allows you to 
modify the new user record before it is saved or to dispatch events. An example 
sso_repository_class might look like this:

```php
<?php
namespace App\Repositories;

use App\Models\User;
use App\Events\UserWasRegistered;

class UserRepository
{
    public function createCognitoUser(User $user): User
    {
        $user->save();
        event(new UserWasRegistered($user));
        
        return $user;
    }
}
```

## Security

If you discover any security-related issues, please email [ben@jelled.com](mailto:ben@jelled.com) instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
