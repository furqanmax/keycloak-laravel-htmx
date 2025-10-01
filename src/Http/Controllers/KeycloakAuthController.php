<?php

namespace KeycloakAuth\Laravel\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use App\Models\User;
use KeycloakAuth\Laravel\Services\KeycloakService;
use KeycloakAuth\Laravel\Services\KeycloakProxyService;
use Laravel\Socialite\Two\User as SocialiteUser;
use GuzzleHttp\Client;

class KeycloakAuthController extends Controller
{
    protected KeycloakService $keycloak;
    protected KeycloakProxyService $proxy;
    
    /**
     * Critical Keycloak cookies to preserve
     */
    protected array $criticalCookies = [
        'KC_RESTART',
        'AUTH_SESSION_ID',
        'AUTH_SESSION_ID_LEGACY'
    ];

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

        // For HTMX requests, we need to handle cookies differently
        if (config('keycloak.auth.htmx_enabled', false)) {
            // Store any existing Keycloak cookies before showing login
            $this->preserveKeycloakCookies($request);
            return view('keycloak-auth::login');
        }
        
        return redirect($this->keycloak->getAuthorizationUrl());
    }
    
    /**
     * Preserve Keycloak cookies for social login flow
     */
    protected function preserveKeycloakCookies(Request $request): void
    {
        $keycloakCookies = [];
        
        foreach ($this->criticalCookies as $cookieName) {
            if ($value = $request->cookie($cookieName)) {
                $keycloakCookies[$cookieName] = $value;
            }
        }
        
        if (!empty($keycloakCookies)) {
            Session::put('preserved_keycloak_cookies', $keycloakCookies);
            Session::put('oauth_timestamp', time());
            Session::save(); // Force session save
        }
    }
    
    /**
     * Initialize Keycloak cookies if they don't exist
     * This is crucial for social login to work properly
     */
    protected function initializeKeycloakCookies(Request $request): bool
    {
        // Check if KC_RESTART cookie exists
        if ($request->cookie('KC_RESTART')) {
            return true;
        }
        
        // Make initial request to Keycloak to get cookies
        $initUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/auth',
            config('keycloak.base_url'),
            config('keycloak.realm')
        );
        
        $params = [
            'client_id' => config('keycloak.client_id'),
            'redirect_uri' => config('keycloak.redirect_uri'),
            'response_type' => 'code',
            'scope' => 'openid'
        ];
        
        $client = new Client([
            'verify' => false,
            'cookies' => true,
            'allow_redirects' => false
        ]);
        
        try {
            $response = $client->get($initUrl . '?' . http_build_query($params));
            $headers = $response->getHeaders();
            
            // Extract and set cookies
            if (isset($headers['Set-Cookie'])) {
                foreach ($headers['Set-Cookie'] as $cookieString) {
                    $this->parseCookieAndSet($cookieString);
                }
                return true;
            }
        } catch (\Exception $e) {
            // Log error but continue
            \Log::warning('Failed to initialize Keycloak cookies: ' . $e->getMessage());
        }
        
        return false;
    }
    
    /**
     * Parse cookie string and set it with proper attributes
     */
    protected function parseCookieAndSet(string $cookieString): void
    {
        // Parse cookie string
        $parts = explode(';', $cookieString);
        $nameValue = array_shift($parts);
        list($name, $value) = explode('=', $nameValue, 2);
        
        // Only set critical cookies
        if (in_array($name, $this->criticalCookies)) {
            $domain = '.auth.eshare.ai';
            
            // Set cookie with SameSite=None for cross-domain
            setcookie(
                $name,
                $value,
                [
                    'expires' => time() + 3600,
                    'path' => '/',
                    'domain' => $domain,
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None'
                ]
            );
        }
    }
    
    /**
     * Restore preserved Keycloak cookies
     */
    protected function restoreKeycloakCookies(): void
    {
        if ($cookies = Session::get('preserved_keycloak_cookies')) {
            $domain = '.auth.eshare.ai';
            
            foreach ($cookies as $name => $value) {
                // Check if cookie doesn't exist
                if (!isset($_COOKIE[$name])) {
                    setcookie(
                        $name,
                        $value,
                        [
                            'expires' => time() + 3600,
                            'path' => '/',
                            'domain' => $domain,
                            'secure' => true,
                            'httponly' => true,
                            'samesite' => 'None'
                        ]
                    );
                    $_COOKIE[$name] = $value;
                }
            }
        }
    }

    /**
     * Handle OAuth callback
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function callback(Request $request)
    {
        // Restore preserved cookies if this is from a social login
        if (Session::get('keycloak_social_login')) {
            $this->restoreKeycloakCookies();
        }
        
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
     * Handle social login redirect
     * This method handles the direct redirect to OAuth providers
     * Implements the same process as simple-social-test.php
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $provider
     * @return \Illuminate\Http\RedirectResponse
     */
    public function socialLogin(Request $request, string $provider)
    {
        // Step 1: Check if we need to get initial Keycloak cookies
        if (!$request->cookie('KC_RESTART')) {
            $this->initializeKeycloakCookies($request);
        }
        
        // Step 2: Save cookies to session before redirecting
        $this->preserveKeycloakCookies($request);
        
        // Step 3: Generate state for OAuth flow
        $state = bin2hex(random_bytes(16));
        Session::put('oauth_state', $state);
        
        // Step 4: Store session data for return
        Session::put('keycloak_social_login', true);
        Session::put('keycloak_provider', $provider);
        Session::save(); // Force session save
        
        // Step 5: Get the authorization URL with social provider hint
        $authUrl = $this->keycloak->getAuthorizationUrl([
            'kc_idp_hint' => $provider,
            'state' => $state
        ]);
        
        return redirect($authUrl);
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
