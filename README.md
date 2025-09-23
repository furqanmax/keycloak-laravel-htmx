# Laravel Keycloak with HTMX Integration

A seamless integration of Keycloak authentication with Laravel, enhanced with HTMX for dynamic, single-page application-like experiences.

## Prerequisites

- PHP 8.0 or higher
- Laravel 9.x or 10.x
- Node.js & NPM (for frontend assets)
- Keycloak server (version 15 or later recommended)

## Installation

1. Install the package via Composer:

```bash
composer require keycloak-auth/laravel
```

2. Publish the configuration file:

```bash
php artisan vendor:publish --tag=keycloak-config
```

3. Configure your `.env` file with your Keycloak settings:

```env
KEYCLOAK_BASE_URL=https://auth.eshare.ai
KEYCLOAK_REALM=leadnest-realm
KEYCLOAK_CLIENT_ID=earnon
KEYCLOAK_CLIENT_SECRET=Iu6vCpdNUoUGtlyMcAntfvSzMPC9lsOx
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
KEYCLOAK_HTMX_ENABLED=true
```

## Frontend Setup

### Required JavaScript Libraries

Include these scripts in your main layout file (usually `resources/views/layouts/app.blade.php`):

```html
<!-- Required for HTMX -->
<script src="https://unpkg.com/htmx.org@1.9.6"></script>

<!-- Optional: Alpine.js for reactive components -->
<script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>

<!-- Optional: Hyperscript for enhanced interactivity -->
<script src="https://unpkg.com/hyperscript.org@0.9.7"></script>

<!-- Keycloak JS Adapter (required for direct client-side auth) -->
<script src="https://${KEYCLOAK_BASE_URL}/js/keycloak.js"></script>
```

### HTMX Configuration

Add this script to initialize HTMX and handle authentication states:

```html
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Initialize HTMX
    htmx.defineExtension('auth-required', {
        onEvent: function(name, evt) {
            if (name === 'htmx:beforeRequest' && !isAuthenticated()) {
                window.location.href = '{{ route("keycloak.login") }}';
                return false;
            }
        }
    });

    // Check authentication status
    function isAuthenticated() {
        return {!! auth()->check() ? 'true' : 'false' !!};
    }
});
</script>
```

### Example Login Button

```html
<!-- Login Button -->
<div hx-get="{{ route('keycloak.login') }}" 
     hx-trigger="click"
     hx-target="#auth-container"
     hx-swap="innerHTML"
     class="cursor-pointer">
    Login with Keycloak
</div>

<!-- Auth Container (will be replaced with login form) -->
<div id="auth-container"></div>
```

## Configuration Options

Edit `config/keycloak.php` to customize the behavior:

```php
return [
    'base_url' => env('KEYCLOAK_BASE_URL'),
    'realm' => env('KEYCLOAK_REALM'),
    'client_id' => env('KEYCLOAK_CLIENT_ID'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
    'redirect_uri' => env('KEYCLOAK_REDIRECT_URI'),
    'htmx_enabled' => env('KEYCLOAK_HTMX_ENABLED', true),
    
    // Enable/disable features that should be shown in the UI
    'features' => [
        'registration' => true,  // Show registration link
        'forgot_password' => true,  // Show forgot password link
        'remember_me' => true,  // Show remember me checkbox
        'social_login' => true,  // Show social login buttons if configured in Keycloak
    ],
    
    // Routes configuration
    'routes' => [
        'login' => 'keycloak.login',
        'logout' => 'keycloak.logout',
        'register' => 'keycloak.register',
        'callback' => 'keycloak.callback',
    ],
];
```

## Available Routes

| Method | URI | Action | Description |
|--------|-----|--------|-------------|
| GET | /auth/login | KeycloakAuthController@login | Initiate login |
| GET | /auth/callback | KeycloakAuthController@callback | OAuth callback URL |
| POST | /auth/logout | KeycloakAuthController@logout | Logout user |
| GET | /auth/user | KeycloakAuthController@user | Get current user info |
| POST | /auth/refresh | KeycloakAuthController@refresh | Refresh access token |

## Middleware

Protect your routes using the included middleware:

```php
// Single route
Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware('keycloak.auth');

// Route group
Route::middleware(['keycloak.auth'])->group(function () {
    // Protected routes here
});
```

## Customization

### Custom Views

Publish the views to customize them:

```bash
php artisan vendor:publish --tag=keycloak-views
```

### Events

Listen for these events in your application:

```php
// In your EventServiceProvider
protected $listen = [
    'keycloak.login' => [
        YourLoginListener::class,
    ],
    'keycloak.logout' => [
        YourLogoutListener::class,
    ],
];
```

## Troubleshooting

- **HTMX not working**: Ensure you've included the HTMX script before your custom scripts
- **CORS issues**: Configure CORS in your Keycloak realm settings
- **Session issues**: Verify your session driver in `config/session.php`
- **HTTPS required**: Make sure your application is served over HTTPS in production

## Security

- Always use HTTPS in production
- Keep your client secret secure
- Regularly rotate your client secrets
- Implement proper session handling
- Follow Keycloak's security best practices

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Example Routes

```php
// routes/web.php
<?php

use Illuminate\Support\Facades\Route;
use KeycloakAuth\Laravel\Facades\KeycloakAuth;

// Public routes
Route::get('/', function () {
    return view('welcome');
});

// Protected routes
Route::middleware('keycloak.auth')->group(function () {
    Route::get('/dashboard', function () {
        $user = KeycloakAuth::user();
        return view('dashboard', compact('user'));
    });
    
    Route::get('/profile', function () {
        return view('profile', ['user' => KeycloakAuth::user()]);
    });
});

// Admin routes (role-based)
Route::middleware(['keycloak.auth'])->group(function () {
    Route::get('/admin', function () {
        $user = KeycloakAuth::user();
        if (!in_array('admin', $user['roles'])) {
            abort(403, 'Unauthorized');
        }
        return view('admin');
    });
});
```

## Example Views

### resources/views/welcome.blade.php
```blade
  <div id="kc-container"
         class="kc-container"
         hx-get="{{ route('keycloak.proxy') }}"
         hx-trigger="load"
         hx-target="#kc-container"
         hx-swap="innerHTML">
        <div class="text-center py-5">
            <div class="spinner-border text-primary mb-3" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="text-muted">Loading secure login...</p>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        (function() {
            // Process HTMX responses from Keycloak proxy
            document.body.addEventListener('htmx:afterSwap', function(ev) {
                if (ev.target.id !== 'kc-container') return;
    
                const container = document.getElementById('kc-container');
    
                // Convert links and forms to HTMX requests
                container.querySelectorAll('a[href]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('javascript:')) {
                        a.setAttribute('hx-get', `{{ route('keycloak.proxy') }}?url=${encodeURIComponent(href)}`);
                        a.setAttribute('hx-target', '#kc-container');
                        a.setAttribute('hx-swap', 'innerHTML');
                        a.removeAttribute('href');
                    }
                });
    
                container.querySelectorAll('form[action]').forEach(form => {
                    const action = form.getAttribute('action');
                    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    
                    if (method === 'POST') {
                        form.setAttribute('hx-post', `{{ route('keycloak.proxy') }}?url=${encodeURIComponent(action)}`);
                    } else {
                        form.setAttribute('hx-get', `{{ route('keycloak.proxy') }}?url=${encodeURIComponent(action)}`);
                    }
                    form.setAttribute('hx-target', '#kc-container');
                    form.setAttribute('hx-swap', 'innerHTML');
                    form.removeAttribute('action');
                });
    
                // Re-process with HTMX
                htmx.process(container);
            });
        })();
    </script>

```

### resources/views/dashboard.blade.php
```blade
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Dashboard</h1>
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">User Information</h5>
                <ul class="list-group">
                    <li class="list-group-item"><strong>ID:</strong> {{ $user['id'] }}</li>
                    <li class="list-group-item"><strong>Username:</strong> {{ $user['username'] }}</li>
                    <li class="list-group-item"><strong>Email:</strong> {{ $user['email'] }}</li>
                    <li class="list-group-item"><strong>Name:</strong> {{ $user['name'] ?? 'N/A' }}</li>
                    <li class="list-group-item"><strong>Roles:</strong> {{ implode(', ', $user['roles']) }}</li>
                </ul>
            </div>
        </div>
        
        <div class="mt-3">
            <a href="/" class="btn btn-secondary">Home</a>
            <form action="{{ route('keycloak.logout') }}" method="POST" class="d-inline">
                @csrf
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
</body>
</html>
```

## Running the Application

1. Start the Laravel development server:
```bash
php artisan serve
```

2. Visit `http://localhost:8000` in your browser

3. Click "Login with Keycloak" to authenticate

4. After successful login, you'll be redirected to the dashboard

## Advanced Usage

### Using in Controllers

```php
<?php

namespace App\Http\Controllers;

use KeycloakAuth\Laravel\Facades\KeycloakAuth;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('keycloak.auth');
    }
    
    public function profile()
    {
        $user = KeycloakAuth::user();
        
        // Check specific role
        $isAdmin = in_array('admin', $user['roles']);
        
        return view('user.profile', compact('user', 'isAdmin'));
    }
    
    public function refreshToken()
    {
        try {
            $tokens = KeycloakAuth::refreshToken();
            return response()->json(['success' => true]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
}
```

### API Authentication

```php
// routes/api.php
Route::middleware('keycloak.auth')->group(function () {
    Route::get('/api/user', function () {
        return response()->json(KeycloakAuth::user());
    });
    
    Route::get('/api/protected', function () {
        return response()->json(['message' => 'This is protected']);
    });
});
```

### Custom Middleware for Roles

```php
// app/Http/Middleware/CheckRole.php
<?php

namespace App\Http\Middleware;

use Closure;
use KeycloakAuth\Laravel\Facades\KeycloakAuth;

class CheckRole
{
    public function handle($request, Closure $next, ...$roles)
    {
        $user = KeycloakAuth::user();
        
        if (!$user) {
            return redirect()->route('keycloak.login');
        }
        
        $userRoles = $user['roles'] ?? [];
        
        if (empty(array_intersect($roles, $userRoles))) {
            abort(403, 'Unauthorized - Missing required role');
        }
        
        return $next($request);
    }
}

// Register in Kernel.php
protected $routeMiddleware = [
    // ...
    'role' => \App\Http\Middleware\CheckRole::class,
];

// Use in routes
Route::middleware(['keycloak.auth', 'role:admin,manager'])->group(function () {
    Route::get('/admin', 'AdminController@index');
});
```

## Troubleshooting

1. **Session Issues**: Clear Laravel cache and sessions:
```bash
php artisan cache:clear
php artisan config:clear
php artisan session:clear
```

2. **CORS Issues**: Add Keycloak domain to CORS configuration in `config/cors.php`

3. **HTTPS Issues**: For local development with HTTPS, use Laravel Valet or configure SSL certificates

## Next Steps

- Implement user profile management
- Add role-based permissions
- Integrate with Laravel policies
- Add API token authentication
- Implement social login buttons
