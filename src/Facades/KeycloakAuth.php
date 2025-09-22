<?php

namespace KeycloakAuth\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string getAuthorizationUrl(array $params = [])
 * @method static array exchangeCodeForTokens(string $code)
 * @method static array|null refreshToken(string $refreshToken = null)
 * @method static object decodeToken(string $token)
 * @method static string logout(string $idToken = null)
 * @method static bool isAuthenticated()
 * @method static array|null user()
 * 
 * @see \KeycloakAuth\Laravel\Services\KeycloakService
 */
class KeycloakAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'keycloak-auth';
    }
}
