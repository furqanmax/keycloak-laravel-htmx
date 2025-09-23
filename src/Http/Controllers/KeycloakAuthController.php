<?php

namespace KeycloakAuth\Laravel\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use App\Models\User;
use KeycloakAuth\Laravel\Services\KeycloakService;
use KeycloakAuth\Laravel\Services\KeycloakProxyService;
use Laravel\Socialite\Two\User as SocialiteUser;

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
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\View\View
     */
    public function login(Request $request)
    {
        if ($this->keycloak->isAuthenticated()) {
            return redirect()->intended(
                config('keycloak.auth.redirect_after_login', '/dashboard')
            );
        }

        return config('keycloak.auth.htmx_enabled', false)
            ? view('keycloak-auth::login')
            : redirect($this->keycloak->getAuthorizationUrl());
    }

    /**
     * Handle OAuth callback
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function callback(Request $request)
    {
        if ($error = $request->get('error')) {
            return $this->handleAuthError($error);
        }

        if (!$code = $request->get('code')) {
            return $this->handleAuthError('No authorization code provided');
        }

        try {
            $tokens = $this->keycloak->exchangeCodeForTokens($code);
            $keycloakUser = $this->keycloak->user();
            
            event('keycloak.login', [$keycloakUser, $tokens]);
            
            $user = $this->findOrCreateUser($keycloakUser);
            Auth::login($user);
            
            return redirect()->intended(
                config('keycloak.auth.redirect_after_login', '/dashboard')
            );
            
        } catch (Exception $e) {
            return $this->handleAuthError($e->getMessage());
        }
    }
    
    /**
     * Find or create a user based on Keycloak user data
     */
    protected function findOrCreateUser(array $keycloakUser): User
    {
        $socialiteUser = (new SocialiteUser)->setRaw($keycloakUser)->map([
            'id' => $keycloakUser['sub'] ?? $keycloakUser['id'] ?? null,
            'name' => $keycloakUser['name'] ?? null,
            'email' => $keycloakUser['email'] ?? null,
            'email_verified' => $keycloakUser['email_verified'] ?? false,
        ]);
        
        return User::updateOrCreate(
            ['email' => $socialiteUser->email],
            [
                'name' => $socialiteUser->name,
                'keycloak_id' => $socialiteUser->id,
                'email_verified_at' => $socialiteUser->email_verified ? now() : null,
            ]
        );
    }
    
    /**
     * Handle authentication errors
     */
    protected function handleAuthError(string $message)
    {
        return redirect()
            ->route('keycloak.login')
            ->with('error', 'Authentication failed: ' . $message);
    }


    /**
     * Logout user
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\RedirectResponse
     */
    public function logout(Request $request)
    {
        $user = $this->keycloak->user();
        $logoutUrl = $this->keycloak->logout();

        event('keycloak.logout', [$user]);
        Auth::logout();
        Session::flush();

        return $request->expectsJson()
            ? response()->json(['redirect' => $logoutUrl])
            : redirect($logoutUrl);
    }

    /**
     * Proxy endpoint for HTMX requests to Keycloak
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function proxy(Request $request)
    {
        return $this->proxy->handleRequest($request);
    }

    /**
     * Refresh token endpoint
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        try {
            if (!$tokens = $this->keycloak->refreshToken()) {
                return response()->json(
                    ['error' => 'Unable to refresh token'],
                    401
                );
            }

            return response()->json([
                'access_token' => $tokens['access_token'],
                'expires_in' => $tokens['expires_in'] ?? 3600,
            ]);
        } catch (Exception $e) {
            return response()->json(
                ['error' => $e->getMessage()],
                401
            );
        }
    }

    /**
     * Get current user info
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function user(Request $request)
    {
        if (!$user = $this->keycloak->user()) {
            return response()->json(
                ['error' => 'Not authenticated'],
                401
            );
        }

        return response()->json($user);
    }
}
