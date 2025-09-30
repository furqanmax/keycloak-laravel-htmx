<?php

namespace KeycloakAuth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class HandleOAuthReturn
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Check if this is a return from OAuth provider
        if ($this->isOAuthReturn($request)) {
            $this->restoreKeycloakCookies($request);
        }
        
        return $next($request);
    }
    
    /**
     * Check if request is returning from OAuth provider
     */
    protected function isOAuthReturn(Request $request): bool
    {
        // Check for OAuth callback parameters
        return $request->has('state') && 
               ($request->has('code') || $request->has('error')) &&
               (str_contains($request->header('referer', ''), 'google.com') ||
                str_contains($request->header('referer', ''), 'facebook.com') ||
                str_contains($request->header('referer', ''), 'github.com'));
    }
    
    /**
     * Restore Keycloak cookies from session
     */
    protected function restoreKeycloakCookies(Request $request): void
    {
        $savedCookies = Session::get('keycloak_proxy_cookies', []);
        
        if (empty($savedCookies)) {
            return;
        }
        
        $keycloakDomain = parse_url(config('keycloak.base_url'), PHP_URL_HOST);
        
        foreach ($savedCookies as $cookie) {
            if (isset($cookie['Name']) && isset($cookie['Value'])) {
                // Set cookie header for the current request
                $request->cookies->set($cookie['Name'], $cookie['Value']);
                
                // Also set for future requests
                setcookie(
                    $cookie['Name'],
                    $cookie['Value'],
                    0, // session cookie
                    '/',
                    $keycloakDomain,
                    true, // secure
                    true, // httponly
                    'None' // SameSite for OAuth
                );
            }
        }
    }
}
