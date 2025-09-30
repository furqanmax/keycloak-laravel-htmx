<?php

namespace KeycloakAuth\Laravel\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Session;

class KeycloakProxyService
{
    protected KeycloakService $keycloak;
    protected Client $httpClient;
    protected CookieJar $cookieJar;

    public function __construct(KeycloakService $keycloak)
    {
        $this->keycloak = $keycloak;
        $this->httpClient = new Client([
            'timeout' => 30,
            'verify' => true,
            'allow_redirects' => false,
            'http_errors' => false,
            'cookies' => true, // Enable cookie handling
        ]);
        $this->initializeCookieJar();
    }

    /**
     * Handle proxy request from HTMX
     */
    public function handleRequest(Request $request): Response
    {
        // Initialize cookie jar from session
        $this->initializeCookieJar();
        
        // Check if returning from social login
        if (Session::get('keycloak_social_login')) {
            Session::forget('keycloak_social_login');
            // Restore cookies from session for social login continuation
            $this->restoreKeycloakSession();
        }

        $targetUrl = $this->determineTargetUrl($request);

        if (!$targetUrl) {
            return response('<div>Invalid proxy request</div>', 400);
        }

        try {
            // Prepare request options
            $options = $this->prepareRequestOptions($request);

            // Make request to Keycloak
            $response = $this->httpClient->request(
                $request->getMethod(),
                $targetUrl,
                $options
            );

            // Update cookies in session
            Session::put('keycloak_proxy_cookies', $this->cookieJar->toArray());

            // Handle redirects
            $finalUrl = $targetUrl;
            while ($response->getStatusCode() >= 300 && $response->getStatusCode() < 400) {
                $location = $response->getHeader('Location')[0] ?? null;

                if (!$location) {
                    break;
                }

                $absoluteLocation = $this->makeAbsoluteUrl($location, $finalUrl);

                // Check if this is a redirect to our callback (successful login)
                if ($this->isCallbackRedirect($absoluteLocation)) {
                    return response('', 200)
                        ->header('HX-Redirect', env('KEYCLOAK_DEFAULT_REDIRECT'));
                }

                // Check if this is an external redirect (social login)
                if ($this->isExternalRedirect($absoluteLocation)) {
                    // Save cookies before redirecting to external provider
                    Session::put('keycloak_proxy_cookies', $this->cookieJar->toArray());
                    Session::put('keycloak_social_login', true);
                    Session::put('keycloak_return_url', $request->fullUrl());
                    Session::save(); // Force session save
                    
                    // For social login, we need to handle this differently
                    // Instead of using HX-Redirect, we need to do a full page redirect
                    // to ensure cookies are properly set
                    
                    // Create a response that will trigger a full page redirect
                    $html = '<script>window.location.href = "' . htmlspecialchars($absoluteLocation) . '";</script>';
                    $html .= '<p>Redirecting to authentication provider...</p>';
                    
                    $response = response($html, 200)
                        ->header('Content-Type', 'text/html');
                    
                    // Set Keycloak cookies in the browser before redirect
                    // These need to be set with SameSite=None for OAuth flow
                    $keycloakDomain = parse_url(config('keycloak.base_url'), PHP_URL_HOST);
                    
                    foreach ($this->cookieJar->toArray() as $cookie) {
                        if (isset($cookie['Name']) && isset($cookie['Value'])) {
                            // Important: Set these cookies in the browser directly
                            setcookie(
                                $cookie['Name'],
                                $cookie['Value'],
                                0, // session cookie
                                '/',
                                $keycloakDomain,
                                true, // secure
                                true, // httponly
                                'None' // SameSite=None for OAuth flow
                            );
                        }
                    }
                    
                    return $response;
                }

                // Internal redirect within Keycloak
                $finalUrl = $absoluteLocation;
                $response = $this->httpClient->get($finalUrl, ['cookies' => $this->cookieJar]);
                Session::put('keycloak_proxy_cookies', $this->cookieJar->toArray());
            }

            // Process and return HTML
            $html = (string) $response->getBody();
            $processedHtml = $this->processHtml($html, $finalUrl);

            return response($processedHtml)
                ->header('X-Keycloak-Base', config('keycloak.base_url'))
                ->header('X-Keycloak-Final-Url', $finalUrl);

        } catch (\Exception $e) {
            return response(
                '<div>Failed to fetch from Keycloak: ' . htmlspecialchars($e->getMessage()) . '</div>',
                502
            );
        }
    }

    /**
     * Initialize cookie jar from session
     */
    protected function initializeCookieJar(): void
    {
        // Get cookies from session or create persistent cookie jar
        $cookies = Session::get('keycloak_proxy_cookies', []);
        
        // Create cookie jar with strict mode disabled to allow third-party cookies
        // This is crucial for social login providers
        $this->cookieJar = new CookieJar(true, $cookies);
        
        // Add any missing Keycloak session cookies
        $this->ensureKeycloakSessionCookies();
    }
    
    /**
     * Ensure Keycloak session cookies are preserved
     */
    protected function ensureKeycloakSessionCookies(): void
    {
        // Get existing Keycloak cookies from browser if available
        $keycloakDomain = parse_url(config('keycloak.base_url'), PHP_URL_HOST);
        
        // Important Keycloak cookies that must be preserved
        $requiredCookies = [
            'AUTH_SESSION_ID',
            'AUTH_SESSION_ID_LEGACY',
            'KC_RESTART',
            'KEYCLOAK_IDENTITY',
            'KEYCLOAK_SESSION',
            'KEYCLOAK_SESSION_LEGACY',
            'KEYCLOAK_LOCALE',
            'KC_STATE_CHECKER'
        ];
        
        foreach ($requiredCookies as $cookieName) {
            // Check if cookie exists in request
            if (request()->cookie($cookieName)) {
                // Add to cookie jar if not already present
                $this->cookieJar->setCookie(new \GuzzleHttp\Cookie\SetCookie([
                    'Name' => $cookieName,
                    'Value' => request()->cookie($cookieName),
                    'Domain' => $keycloakDomain,
                    'Path' => '/',
                    'Secure' => true,
                    'HttpOnly' => true,
                    'SameSite' => 'None' // Allow cross-site for OAuth flow
                ]));
            }
        }
        
        // Also check for cookies in session (from previous requests)
        $sessionCookies = Session::get('keycloak_proxy_cookies', []);
        foreach ($sessionCookies as $cookie) {
            if (isset($cookie['Name']) && in_array($cookie['Name'], $requiredCookies)) {
                $this->cookieJar->setCookie(new \GuzzleHttp\Cookie\SetCookie([
                    'Name' => $cookie['Name'],
                    'Value' => $cookie['Value'] ?? '',
                    'Domain' => $cookie['Domain'] ?? $keycloakDomain,
                    'Path' => $cookie['Path'] ?? '/',
                    'Secure' => $cookie['Secure'] ?? true,
                    'HttpOnly' => $cookie['HttpOnly'] ?? true,
                    'SameSite' => 'None'
                ]));
            }
        }
    }
    
    /**
     * Restore Keycloak session after social login
     */
    protected function restoreKeycloakSession(): void
    {
        // Restore all cookies from session
        $savedCookies = Session::get('keycloak_proxy_cookies', []);
        
        if (!empty($savedCookies)) {
            // Recreate cookie jar with saved cookies
            $this->cookieJar = new CookieJar(true, $savedCookies);
            
            // Ensure domain and path are set correctly for all cookies
            $keycloakDomain = parse_url(config('keycloak.base_url'), PHP_URL_HOST);
            
            foreach ($this->cookieJar->toArray() as $cookie) {
                // Update domain if needed
                if (!isset($cookie['Domain']) || $cookie['Domain'] !== $keycloakDomain) {
                    $cookie['Domain'] = $keycloakDomain;
                    $cookie['Path'] = '/';
                    $cookie['Secure'] = true;
                    $cookie['SameSite'] = 'None';
                }
            }
        }
    }

    /**
     * Determine target URL for proxy request
     */
    protected function determineTargetUrl(Request $request): ?string
    {
        $url = $request->get('url');

        if ($url) {
            // Validate URL is within Keycloak domain
            $baseUrl = config('keycloak.base_url');
            if (strpos($url, $baseUrl) !== 0) {
                return null;
            }
            return $url;
        }

        // Default to login page
        return $this->keycloak->getAuthorizationUrl();
    }

    /**
     * Prepare request options for Guzzle
     */
    protected function prepareRequestOptions(Request $request): array
    {
        $options = [
            'cookies' => $this->cookieJar,
            'headers' => [
                'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            ],
        ];

        // Add referer if present
        if ($request->headers->has('referer')) {
            $options['headers']['Referer'] = $request->headers->get('referer');
        }

        // Add form params for POST requests
        if ($request->isMethod('POST')) {
            $options['form_params'] = $request->all();
        }

        return $options;
    }

    /**
     * Check if URL is a callback redirect
     */
    protected function isCallbackRedirect(string $url): bool
    {
        $redirectUri = config('keycloak.redirect_uri');
        $isCallback = strpos($url, $redirectUri) === 0;

        // If this is a callback URL, set the Laravel session
        if ($isCallback) {
            // Get the authorization code from the URL
            $query = parse_url($url, PHP_URL_QUERY);
            parse_str($query, $params);

            if (isset($params['code'])) {
                // Exchange the authorization code for tokens
                $tokens = $this->keycloak->exchangeCodeForTokens($params['code']);

                // Get user info
                $user = $this->keycloak->user();

                // Set Laravel session
                Session::put('keycloak_user', $user);
                Session::put('keycloak_tokens', $tokens);

                // Log the user in with Laravel's auth system
                if (config('keycloak.auth.guard')) {
                    $guard = auth()->guard(config('keycloak.auth.guard'));
                    if (method_exists($guard, 'loginUsingId')) {
                        $guard->loginUsingId($user['sub'] ?? $user['id'] ?? null);
                    }
                }
            }
        }

        return $isCallback;
    }

    /**
     * Check if URL is an external redirect
     */
    protected function isExternalRedirect(string $url): bool
    {
        $baseUrl = config('keycloak.base_url');
        // Check if it's not a Keycloak URL and not our app URL
        $isExternal = strpos($url, $baseUrl) !== 0 && strpos($url, config('app.url')) !== 0;
        
        // Also check for known OAuth provider domains
        $oauthProviders = [
            'accounts.google.com',
            'facebook.com',
            'github.com',
            'microsoft.com',
            'linkedin.com'
        ];
        
        foreach ($oauthProviders as $provider) {
            if (strpos($url, $provider) !== false) {
                return true;
            }
        }
        
        return $isExternal;
    }

    /**
     * Make relative URL absolute
     */
    protected function makeAbsoluteUrl(string $url, string $baseUrl): string
    {
        // Already absolute
        if (preg_match('~^https?://~i', $url)) {
            return $url;
        }

        $base = parse_url($baseUrl);
        $scheme = $base['scheme'] ?? 'https';
        $host = $base['host'] ?? '';

        // Protocol relative
        if (strpos($url, '//') === 0) {
            return $scheme . ':' . $url;
        }

        // Root relative
        if (strpos($url, '/') === 0) {
            return $scheme . '://' . $host . $url;
        }

        // Relative path
        $path = $base['path'] ?? '/';
        $dir = rtrim(dirname($path), '/');
        return $scheme . '://' . $host . ($dir ? $dir . '/' : '/') . ltrim($url, '/');
    }

    /**
     * Process HTML to extract body content and fix URLs
     */
    protected function processHtml(string $html, string $finalUrl): string
    {
        // Extract body content if present
        if (preg_match('/<body[^>]*>(.*?)<\/body>/is', $html, $matches)) {
            $html = $matches[1];
        }

        // Fix relative URLs
        $baseUrl = config('keycloak.base_url');
        $html = $this->rewriteUrls($html, $finalUrl, $baseUrl);

        return $html;
    }

    /**
     * Rewrite relative URLs to absolute
     */
    protected function rewriteUrls(string $html, string $finalUrl, string $baseUrl): string
    {
        // This is a simplified version - in production, use DOMDocument
        $patterns = [
            // href attributes
            '/href=(["\'])(?!https?:\/\/)([^"\']+)\1/i',
            // src attributes
            '/src=(["\'])(?!https?:\/\/)([^"\']+)\1/i',
            // action attributes
            '/action=(["\'])(?!https?:\/\/)([^"\']+)\1/i',
        ];

        foreach ($patterns as $pattern) {
            $html = preg_replace_callback($pattern, function ($matches) use ($finalUrl, $baseUrl) {
                $quote = $matches[1];
                $url = $matches[2];
                $absoluteUrl = $this->makeAbsoluteUrl($url, $finalUrl);
                return sprintf('%s=%s%s%s',
                    substr($matches[0], 0, strpos($matches[0], '=')),
                    $quote,
                    $absoluteUrl,
                    $quote
                );
            }, $html);
        }

        return $html;
    }
}
