<?php

namespace KeycloakAuth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use KeycloakAuth\Laravel\Services\KeycloakService;

class KeycloakAuthenticate
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
        if (!$this->keycloak->isAuthenticated()) {
            if ($request->ajax() || $request->wantsJson()) {
                return response()->json(['error' => 'Unauthenticated'], 401);
            }
            
            // Store intended URL
            session()->put('url.intended', $request->fullUrl());
            
            return redirect()->route('keycloak.login');
        }

        // Check if token needs refresh
        if (config('keycloak.auth.auto_refresh')) {
            $this->checkAndRefreshToken();
        }

        // Add user to request
        $request->attributes->set('keycloak_user', $this->keycloak->user());

        return $next($request);
    }

    /**
     * Check if token needs refresh and refresh if necessary
     */
    protected function checkAndRefreshToken(): void
    {
        $token = session()->get('keycloak_token');
        if (!$token) {
            return;
        }

        try {
            $decoded = $this->keycloak->decodeToken($token);
            $expiresIn = $decoded->exp - time();
            
            // Refresh if token expires soon
            if ($expiresIn < config('keycloak.auth.refresh_threshold', 60)) {
                $this->keycloak->refreshToken();
            }
        } catch (\Exception $e) {
            // If token is invalid, try to refresh
            $this->keycloak->refreshToken();
        }
    }
}
