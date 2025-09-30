# Keycloak HTMX Social Login Fix

## Problem
When using HTMX to proxy Keycloak authentication forms, clicking on social login providers (like Google) causes a "Restart login cookie not found" error. This happens because:

1. The browser redirects to the OAuth provider (Google) directly
2. Keycloak session cookies (especially `KC_RESTART`) are lost in the redirect flow
3. When returning from Google, Keycloak can't find the session cookies

## Solution Overview

The fix involves multiple components working together to preserve cookies across the OAuth flow:

### 1. Updated KeycloakProxyService
- Detects external OAuth redirects
- Sets cookies with `SameSite=None` for cross-site OAuth flow
- Preserves session cookies before external redirects
- Uses JavaScript redirect instead of HTMX for social providers

### 2. New OAuth Middleware
- Restores Keycloak cookies when returning from OAuth providers
- Located at: `src/Http/Middleware/HandleOAuthReturn.php`

### 3. Dedicated Social Login Route
- Direct redirect to Keycloak with provider hint
- Bypasses HTMX proxy for OAuth flow
- Route: `/auth/social/{provider}`

### 4. Updated JavaScript Handler
- Intercepts social login links
- Routes them through dedicated endpoint
- Handles OAuth callbacks properly

## Configuration

### 1. Register the Middleware
Add to your `app/Http/Kernel.php`:

```php
protected $middlewareGroups = [
    'web' => [
        // ... other middleware
        \KeycloakAuth\Laravel\Http\Middleware\HandleOAuthReturn::class,
    ],
];
```

### 2. Environment Variables
Ensure these are set in your `.env`:

```env
KEYCLOAK_BASE_URL=https://auth.eshare.ai
KEYCLOAK_REALM=earnon-realm
KEYCLOAK_CLIENT_ID=earnon
KEYCLOAK_CLIENT_SECRET=Iu6vCpdNUoUGtlyMcAntfvSzMPC9lsOx
KEYCLOAK_REDIRECT_URI=http://localhost:8000/auth/callback
KEYCLOAK_HTMX_ENABLED=true

# Cookie settings for OAuth
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=none
```

### 3. Web Server Configuration
For Apache, add to `.htaccess`:

```apache
<IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*)$ "$1; SameSite=None; Secure"
</IfModule>
```

For Nginx:

```nginx
proxy_cookie_path / "/; SameSite=None; Secure";
```

## How It Works

### Normal Login Flow (Username/Password)
1. HTMX loads Keycloak form via proxy
2. User submits credentials
3. Proxy handles the request with preserved cookies
4. Authentication completes within HTMX context

### Social Login Flow (Google/Facebook/etc)
1. User clicks social login button
2. JavaScript intercepts the click
3. Routes to `/auth/social/{provider}` (full page redirect)
4. Server preserves cookies and redirects to OAuth provider
5. User authenticates with provider
6. Provider redirects back to Keycloak
7. Keycloak redirects to our callback
8. Middleware restores cookies
9. Authentication completes

## Testing

1. Clear all cookies and sessions
2. Navigate to your login page
3. Click "Login with Google"
4. Complete Google authentication
5. Should redirect back successfully

## Troubleshooting

### Still Getting Cookie Error?

1. **Check HTTPS**: Social login requires HTTPS in production
2. **Clear Browser Cache**: Old cookies might interfere
3. **Check Console**: Look for JavaScript errors
4. **Verify Keycloak Config**: Ensure redirect URIs are correct

### Debug Mode

Enable debug logging in `KeycloakProxyService`:

```php
\Log::debug('Keycloak cookies', [
    'cookies' => $this->cookieJar->toArray(),
    'session' => Session::all()
]);
```

## Security Considerations

1. **SameSite=None**: Required for OAuth but less secure
2. **HTTPS Required**: Always use HTTPS in production
3. **Session Security**: Ensure Laravel sessions are secure
4. **CORS Headers**: May need configuration for cross-origin requests

## Files Modified

- `/src/Services/KeycloakProxyService.php` - Cookie handling improvements
- `/src/Http/Controllers/KeycloakAuthController.php` - Social login method
- `/src/Http/Middleware/HandleOAuthReturn.php` - New middleware
- `/routes/web.php` - New social login route
- `/resources/views/login.blade.php` - JavaScript interceptor

## Notes

- This solution maintains HTMX for regular login while using direct redirects for OAuth
- Cookies are preserved across the entire flow
- Compatible with Google, Facebook, GitHub, Microsoft, and LinkedIn providers
