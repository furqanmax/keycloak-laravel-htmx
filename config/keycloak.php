<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Keycloak Server Configuration
    |--------------------------------------------------------------------------
    |
    | Configure your Keycloak server connection details here.
    |
    */
    
    'base_url' => env('KEYCLOAK_BASE_URL', 'https://auth.eshare.ai'),
    'realm' => env('KEYCLOAK_REALM', 'leadnest-realm'),
    'client_id' => env('KEYCLOAK_CLIENT_ID', 'earnon'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', ''),
    'redirect_uri' => env('KEYCLOAK_REDIRECT_URI', config('app.url') . '/auth/callback'),
    
    /*
    |--------------------------------------------------------------------------
    | Authentication Settings
    |--------------------------------------------------------------------------
    |
    | Configure authentication behavior and preferences.
    |
    */
    
    'auth' => [
        // Enable or disable HTMX mode
        'htmx_enabled' => env('KEYCLOAK_HTMX_ENABLED', true),
        
        // Session key prefix
        'session_prefix' => 'keycloak_',
        
        // Token refresh threshold (seconds before expiry)
        'refresh_threshold' => 60,
        
        // Enable auto-refresh of tokens
        'auto_refresh' => true,
        
        // Default scopes
        'scopes' => ['openid', 'profile', 'email'],
        
        // Enable social login providers
        'social_providers' => [
            'google' => env('KEYCLOAK_SOCIAL_GOOGLE', true),
            'facebook' => env('KEYCLOAK_SOCIAL_FACEBOOK', false),
            'github' => env('KEYCLOAK_SOCIAL_GITHUB', false),
        ],
    ],
    
    /*
    |--------------------------------------------------------------------------
    | UI Configuration
    |--------------------------------------------------------------------------
    |
    | Customize the authentication UI appearance.
    |
    */
    
    'ui' => [
        // Use embedded login (HTMX) or redirect to Keycloak
        'embedded_login' => true,
        
        // Custom branding
        'brand_name' => env('APP_NAME', 'Your Application'),
        'brand_logo' => null,
        
        // Hero section settings
        'hero' => [
            'title' => 'Secure Authentication',
            'subtitle' => 'Powered by Keycloak SSO',
            'show_features' => true,
        ],
        
        // Custom CSS classes
        'css_classes' => [
            'container' => 'auth-container',
            'form' => 'keycloak-form',
            'button' => 'btn btn-primary',
        ],
    ],
    
    /*
    |--------------------------------------------------------------------------
    | Routes Configuration
    |--------------------------------------------------------------------------
    |
    | Define custom route paths for authentication endpoints.
    |
    */
    
    'routes' => [
        'prefix' => 'auth',
        'middleware' => ['web'],
        'login' => 'login',
        'logout' => 'logout',
        'callback' => 'callback',
        'proxy' => 'proxy',
        'refresh' => 'refresh',
        'user' => 'user',
    ],
    
    /*
    |--------------------------------------------------------------------------
    | Guard Configuration
    |--------------------------------------------------------------------------
    |
    | Configure Laravel guard integration.
    |
    */
    
    'guard' => [
        // Use Keycloak as a Laravel guard
        'enabled' => true,
        
        // Guard name
        'name' => 'keycloak',
        
        // User provider
        'provider' => 'keycloak',
    ],
    
    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Configure caching for Keycloak data.
    |
    */
    
    'cache' => [
        // Cache public keys
        'public_keys_ttl' => 3600,
        
        // Cache user permissions
        'permissions_ttl' => 300,
        
        // Cache driver
        'driver' => env('CACHE_DRIVER', 'file'),
    ],
];
