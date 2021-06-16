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
    | User Provider
    |--------------------------------------------------------------------------
    | The cognito_uuid_key is the name of the column where the cognito users
    | UUIDs are stored. Cognito guard will look in that column to match a given
    | access token with an existing Laravel user.
    |
    |
    */

    'cognito_uuid_key'  => 'cognito_uuid',
];
