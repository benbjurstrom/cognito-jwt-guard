<?php

return [

    /*
    |--------------------------------------------------------------------------
    | AWS Cognito User Pool and App Client Settings
    |--------------------------------------------------------------------------
    | Provide the cognito user pool id and user pool region.
    |
    | See this guide for help setting up a user pool:
    | https://serverless-stack.com/chapters/create-a-cognito-user-pool.html
    |
    |
    */

    'user_pool_id'      => env('AWS_COGNITO_USER_POOL_ID'),
    'user_pool_region'  => env('AWS_COGNITO_REGION'),
    'user_pool_client_id'  => env('AWS_COGNITO_CLIENT_ID'),

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
];
