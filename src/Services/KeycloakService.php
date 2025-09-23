<?php

namespace KeycloakAuth\Laravel\Services;

use App\User;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Cache;
use Exception;

class KeycloakService
{
    protected Client $httpClient;
    protected string $baseUrl;
    protected string $realm;
    protected string $clientId;
    protected string $clientSecret;
    protected string $redirectUri;
    public function __construct(
        string $baseUrl,
        string $realm,
        string $clientId,
        string $clientSecret,
        string $redirectUri
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->realm = $realm;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        
        $this->httpClient = new Client([
            'base_uri' => $this->baseUrl,
            'timeout' => 30,
            'verify' => true,
        ]);
    }


    /**
     * Get the authorization URL
     */
    public function getAuthorizationUrl(array $params = []): string
    {
        $defaultParams = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'prompt' => 'login',
        ];

        $params = array_merge($defaultParams, $params);
        $query = http_build_query($params);

        return "{$this->baseUrl}/realms/{$this->realm}/protocol/openid-connect/auth?{$query}";
    }

    /**
     * Exchange authorization code for tokens
     */
    public function exchangeCodeForTokens(string $code): array
    {
        $response = $this->httpClient->post("/realms/{$this->realm}/protocol/openid-connect/token", [
            'form_params' => [
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
            ],
        ]);

        $tokens = json_decode($response->getBody()->getContents(), true);
        
        // Store tokens in session
        Session::put('keycloak_token', $tokens['access_token']);
        Session::put('keycloak_refresh_token', $tokens['refresh_token'] ?? null);
        Session::put('keycloak_id_token', $tokens['id_token'] ?? null);

        $userInfo = $this->decodeToken($tokens['access_token']);

        $user = User::updateOrCreate(
        // 🔎 Search condition (unique key)
            ['email' => $userInfo->email],

            // 📝 Values to update if found, or insert if not
            [
                'username' => $userInfo->email,
                'name'     => $userInfo->name,
                'password' => bcrypt(str()->random(16)),
                // 'provider'    => $provider,
                // 'provider_id' => $socialUser->getId(),
            ]
        );
        // Log the user in
        Auth::login($user);
        // Decode and store user info
        $userInfo = $this->decodeToken($tokens['access_token']);
        Session::put('keycloak_user', $this->formatUserInfo($userInfo));
        
        return $tokens;
    }

    /**
     * Refresh access token
     */
    public function refreshToken(string $refreshToken = null): ?array
    {
        $refreshToken = $refreshToken ?: Session::get('keycloak_refresh_token');
        
        if (!$refreshToken) {
            return null;
        }

        try {
            $response = $this->httpClient->post("/realms/{$this->realm}/protocol/openid-connect/token", [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'refresh_token' => $refreshToken,
                ],
            ]);

            $tokens = json_decode($response->getBody()->getContents(), true);
            
            // Update stored tokens
            Session::put('keycloak_token', $tokens['access_token']);
            Session::put('keycloak_refresh_token', $tokens['refresh_token'] ?? $refreshToken);
            
            return $tokens;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Validate and decode JWT token
     */
    public function decodeToken(string $token): object
    {
        // Get public keys from Keycloak
        $publicKeys = $this->getPublicKeys();
        
        // Try to decode with each key until one works
        foreach ($publicKeys as $key) {
            try {
                return JWT::decode($token, new Key($key, 'RS256'));
            } catch (Exception $e) {
                continue;
            }
        }
        
        throw new Exception('Unable to decode token with any available public key');
    }

    /**
     * Get public keys from Keycloak
     */
    protected function getPublicKeys(): array
    {
        $cacheKey = "keycloak_public_keys_{$this->realm}";
        
        return Cache::remember($cacheKey, 3600, function () {
            $response = $this->httpClient->get("/realms/{$this->realm}/protocol/openid-connect/certs");
            $jwks = json_decode($response->getBody()->getContents(), true);
            
            $keys = [];
            foreach ($jwks['keys'] as $keyData) {
                if ($keyData['kty'] === 'RSA') {
                    $keys[] = $this->buildPublicKey($keyData);
                }
            }
            
            return $keys;
        });
    }


    /**
     * Build PEM format public key from JWK
     */
    protected function buildPublicKey(array $keyData): string
    {
        $modulus = $this->base64UrlDecode($keyData['n']);
        $exponent = $this->base64UrlDecode($keyData['e']);

        $components = [
            'modulus' => pack('Ca*a*', 2, $this->encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, $this->encodeLength(strlen($exponent)), $exponent),
        ];

        $rsaPublicKey = pack(
            'Ca*a*a*',
            48,
            $this->encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        $rsaOID = pack('H*', '300d06092a864886f70d0101010500');
        $rsaPublicKey = chr(0) . $rsaPublicKey;
        $rsaPublicKey = chr(3) . $this->encodeLength(strlen($rsaPublicKey)) . $rsaPublicKey;

        $rsaPublicKey = pack(
            'Ca*a*',
            48,
            $this->encodeLength(strlen($rsaOID . $rsaPublicKey)),
            $rsaOID . $rsaPublicKey
        );

        return "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($rsaPublicKey), 64) .
            "-----END PUBLIC KEY-----";
    }

    /**
     * Encode ASN.1 length
     */
    protected function encodeLength(int $length): string
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Base64 URL decode
     */
    protected function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }

    /**
     * Format user info from token
     */
    protected function formatUserInfo(object $tokenData): array
    {
        return [
            'id' => $tokenData->sub ?? null,
            'username' => $tokenData->preferred_username ?? null,
            'email' => $tokenData->email ?? null,
            'email_verified' => $tokenData->email_verified ?? false,
            'name' => $tokenData->name ?? null,
            'given_name' => $tokenData->given_name ?? null,
            'family_name' => $tokenData->family_name ?? null,
            'roles' => $tokenData->realm_access->roles ?? [],
            'groups' => $tokenData->groups ?? [],
        ];
    }



    /**
     * Logout user
     */
    public function logout(string $idToken = null): string
    {
        $idToken = $idToken ?: Session::get('keycloak_id_token');
        
        // Clear session
        Session::forget(['keycloak_token', 'keycloak_refresh_token', 'keycloak_id_token', 'keycloak_user', 'keycloak_cookies']);
        
        // Build logout URL
        $params = [
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => url('/'),
        ];
        
        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }
        
        $query = http_build_query($params);
        return "{$this->baseUrl}/realms/{$this->realm}/protocol/openid-connect/logout?{$query}";
    }

    /**
     * Check if user is authenticated
     */
    public function isAuthenticated(): bool
    {
        return Session::has('keycloak_token');
    }

    /**
     * Get authenticated user
     */
    public function user(): ?array
    {
        return Session::get('keycloak_user');
    }
}
