<?php

namespace KeycloakAuth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use KeycloakAuth\Laravel\Services\KeycloakService;

class KeycloakGuest
{
    protected KeycloakService $keycloak;

    public function __construct(KeycloakService $keycloak)
    {
        $this->keycloak = $keycloak;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle(Request $request, Closure $next, $guard = null)
    {
        if ($this->keycloak->isAuthenticated()) {
            // User is authenticated, redirect to dashboard or intended URL
            return redirect('/dashboard');
        }

        return $next($request);
    }
}
