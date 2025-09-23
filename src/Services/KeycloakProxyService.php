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
                    return response('', 200)
                        ->header('HX-Redirect', $absoluteLocation);
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
        $cookies = Session::get('keycloak_proxy_cookies', []);
        $this->cookieJar = new CookieJar(false, $cookies);
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
        return strpos($url, $baseUrl) !== 0;
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
