<?php

use Illuminate\Support\Facades\Route;
use KeycloakAuth\Laravel\Http\Controllers\KeycloakAuthController;

Route::group([
    'prefix' => config('keycloak.routes.prefix', 'auth'),
    'middleware' => config('keycloak.routes.middleware', ['web']),
    'as' => 'keycloak.',
], function () {
    
    // Authentication routes
    Route::get(config('keycloak.routes.login', 'login'), [KeycloakAuthController::class, 'login'])
        ->name('login');
    
    Route::get(config('keycloak.routes.callback', 'callback'), [KeycloakAuthController::class, 'callback'])
        ->name('callback');
    
    Route::post(config('keycloak.routes.logout', 'logout'), [KeycloakAuthController::class, 'logout'])
        ->name('logout');
    
    // HTMX proxy endpoint
    Route::match(['GET', 'POST'], config('keycloak.routes.proxy', 'proxy'), [KeycloakAuthController::class, 'proxy'])
        ->name('proxy');
    
    // API endpoints
    Route::post(config('keycloak.routes.refresh', 'refresh'), [KeycloakAuthController::class, 'refresh'])
        ->name('refresh');
    
    Route::get(config('keycloak.routes.user', 'user'), [KeycloakAuthController::class, 'user'])
        ->name('user')
        ->middleware('keycloak.auth');
});
