<?php

namespace KeycloakAuth\Laravel\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KeycloakAuth\Laravel\Services\KeycloakService;
use KeycloakAuth\Laravel\Services\KeycloakProxyService;

class KeycloakAuthController extends Controller
{
    protected KeycloakService $keycloak;
    protected KeycloakProxyService $proxy;

    public function __construct(KeycloakService $keycloak, KeycloakProxyService $proxy)
    {
        $this->keycloak = $keycloak;
        $this->proxy = $proxy;
    }

    /**
     * Show the login page (HTMX or redirect)
     */
    public function login(Request $request)
    {
        // Check if already authenticated
        if ($this->keycloak->isAuthenticated()) {
            return redirect()->intended(config('keycloak.auth.redirect_after_login', env('KEYCLOAK_DEFAULT_REDIRECT')));
        }

        // If HTMX is enabled, show embedded login
        if (config('keycloak.auth.htmx_enabled')) {
            return view('keycloak-auth::login');
        }

        // Otherwise, redirect to Keycloak
        return redirect($this->keycloak->getAuthorizationUrl());
    }

    /**
     * Handle OAuth callback
     */
    public function callback(Request $request)
    {
        $code = $request->get('code');
        $error = $request->get('error');

        if ($error) {
            return redirect()->route('keycloak.login')
                ->with('error', 'Authentication failed: ' . $error);
        }

        if (!$code) {
            return redirect()->route('keycloak.login')
                ->with('error', 'No authorization code provided');
        }

        try {
            // Exchange code for tokens
            $tokens = $this->keycloak->exchangeCodeForTokens($code);

            // Get user info
            $keycloakUser = $this->keycloak->user();

            // Fire login event with the raw Keycloak user data
            event('keycloak.login', [$keycloakUser, $tokens]);

            // Prepare Socialite user data
            $socialiteUser = (new \Laravel\Socialite\Two\User)->setRaw($keycloakUser)
                ->map([
                    'id' => $keycloakUser['sub'] ?? $keycloakUser['id'] ?? null,
                    'name' => $keycloakUser['name'] ?? null,
                    'email' => $keycloakUser['email'] ?? null,
                    'email_verified' => $keycloakUser['email_verified'] ?? false,
                    'nickname' => $keycloakUser['preferred_username'] ?? null,
                    'avatar' => null, // Add avatar URL if available in Keycloak
                ]);

            // Store tokens in session
            session(['keycloak_token' => $tokens]);

            // Get the user from your database or create a new one
            $user = \App\Models\User::updateOrCreate(
                ['email' => $socialiteUser->email],
                [
                    'name' => $socialiteUser->name,
                    'keycloak_id' => $socialiteUser->id,
                    'email_verified_at' => $socialiteUser->email_verified ? now() : null,
                ]
            );

            // Log the user in
            \Auth::login($user);

            // Get the intended URL or use default
            $redirectUrl = session()->pull('url.intended', config('keycloak.auth.redirect_after_login', '/'));
            return redirect($redirectUrl);

        } catch (\Exception $e) {
            return redirect()->route('keycloak.login')
                ->with('error', 'Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Logout user
     */
    public function logout(Request $request)
    {
        $logoutUrl = $this->keycloak->logout();

        // Fire logout event
        event('keycloak.logout', [$this->keycloak->user()]);

        // If it's an AJAX request, return JSON
        if ($request->ajax() || $request->wantsJson()) {
            return response()->json(['redirect' => $logoutUrl]);
        }

        return redirect($logoutUrl);
    }

    /**
     * Proxy endpoint for HTMX requests to Keycloak
     */
    public function proxy(Request $request)
    {
        // This handles HTMX requests to Keycloak
        return $this->proxy->handleRequest($request);
    }

    /**
     * Refresh token endpoint
     */
    public function refresh(Request $request)
    {
        try {
            $tokens = $this->keycloak->refreshToken();

            if (!$tokens) {
                return response()->json(['error' => 'Unable to refresh token'], 401);
            }

            return response()->json([
                'access_token' => $tokens['access_token'],
                'expires_in' => $tokens['expires_in'] ?? 3600,
            ]);

        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }

    /**
     * Get current user info
     */
    public function user(Request $request)
    {
        $user = $this->keycloak->user();

        if (!$user) {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        return response()->json($user);
    }
}
