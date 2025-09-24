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
composer require maxjack/keycloak-auth
```

2. Configure your `.env` file with your Keycloak settings:
Note : KEYCLOAK_DEFAULT_REDIRECT assign the path where you want to redirect after successful login

```env
KEYCLOAK_BASE_URL=https://auth.keycloak.ai
KEYCLOAK_REALM=realm
KEYCLOAK_CLIENT_ID=client
KEYCLOAK_CLIENT_SECRET=secret
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
KEYCLOAK_HTMX_ENABLED=true
KEYCLOAK_DEFAULT_REDIRECT=/dashboard
```
note : add the config to env file before executing the next step

3. Publish the configuration file:

```bash
php artisan vendor:publish --tag=keycloak-config

php artisan vendor:publish --tag=public

php artisan vendor:publish --tag=keycloak-services
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

<!-- CSS -->
<link rel="stylesheet" href="{{ asset('vendor/keycloak-auth/css/keycloak-styles.css') }}">

```




## Example Views
Include these scripts where you want to show the login  (usually `resources/views/welcome.blade.php`):

### resources/views/welcome.blade.php
```blade
  <div id="kc-container"
                             class="kc-container position-relative"
                             hx-get="{{ route('keycloak.proxy') }}"
                             hx-trigger="load"
                             hx-target="#kc-container"
                             hx-swap="innerHTML">
                            <div class="text-center py-5" id="kc-loader">
                                <div class="spinner-border text-primary mb-3" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                                <p class="text-muted">Loading secure login...</p>
                            </div>
                        </div>

                        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
                        <script hx-ext="ignore">
                            // Authentication Handler - Namespace to prevent conflicts
                            window.AuthHandler = (function() {
                                'use strict';

                                // Private variables
                                let container = null;
                                let isInitialized = false;

                                // Configuration
                                const CONFIG = {
                                    containerId: 'kc-container',
                                    loaderOverlayId: 'kc-loader-overlay',
                                    zIndex: '1050',
                                    keycloakRoute: '{{ route("keycloak.proxy") }}'
                                };


                                // CSRF token injection
                                const csrfHandler = {
                                    addCsrfToForms: function(root = document) {
                                        const tokenMeta = utils.safeQuerySelector('meta[name="csrf-token"]');
                                        if (!tokenMeta) return;
                                        const csrfToken = tokenMeta.getAttribute("content");

                                        utils.safeQuerySelectorAll("form", root).forEach(form => {
                                            if (!form.querySelector("input[name='_token']")) {
                                                let hiddenInput = document.createElement("input");
                                                hiddenInput.type = "hidden";
                                                hiddenInput.name = "_token";
                                                hiddenInput.value = csrfToken;
                                                form.appendChild(hiddenInput);
                                            }
                                        });
                                    }
                                };

                                // HTMX integration
                                const htmxIntegration = {
                                    rewireLinks: function(context) {
                                        if (!context) return;

                                        const links = utils.safeQuerySelectorAll('a[href]', context);

                                        links.forEach(link => {
                                            const href = link.getAttribute('href');
                                            if (href && !href.startsWith('javascript:') && !link.dataset.authProcessed) {
                                                try {
                                                    const proxyUrl = `${CONFIG.keycloakRoute}?url=${encodeURIComponent(href)}`;
                                                    link.setAttribute('hx-get', proxyUrl);
                                                    link.setAttribute('hx-target', `#${CONFIG.containerId}`);
                                                    link.setAttribute('hx-swap', 'innerHTML');
                                                    link.removeAttribute('href');
                                                    link.classList.add('keycloak-link');
                                                    link.dataset.authProcessed = 'true';
                                                } catch (e) {
                                                    console.error('AuthHandler: Error processing link', href, e);
                                                }
                                            }
                                        });
                                    },

                                    rewireForms: function(context) {
                                        if (!context) return;

                                        const forms = utils.safeQuerySelectorAll('form[action]', context);

                                        csrfHandler.addCsrfToForms(context);


                                        forms.forEach(form => {
                                            if (form.dataset.authProcessed) return;

                                            const action = form.getAttribute('action');
                                            const method = (form.getAttribute('method') || 'GET').toUpperCase();

                                            if (action) {
                                                try {
                                                    console.log(CONFIG.keycloakRoute+'?url='+encodeURIComponent(action))
                                                    const proxyUrl = `${CONFIG.keycloakRoute}?url=${encodeURIComponent(action)}`;

                                                    if (method === 'POST') {
                                                        form.setAttribute('hx-post', proxyUrl);
                                                    } else {
                                                        form.setAttribute('hx-get', proxyUrl);
                                                    }

                                                    form.setAttribute('hx-target', `#${CONFIG.containerId}`);
                                                    form.setAttribute('hx-swap', 'innerHTML');
                                                    form.removeAttribute('action');
                                                    form.dataset.authProcessed = 'true';
                                                } catch (e) {
                                                    console.error('AuthHandler: Error processing form', action, e);
                                                }
                                            }
                                        });
                                    },

                                    processContent: function(context) {
                                        if (!context) return;

                                        this.rewireLinks(context);
                                        this.rewireForms(context);
                                        passwordToggle.init(context);

                                        // Process with HTMX if available
                                        if (window.htmx && typeof window.htmx.process === 'function') {
                                            try {
                                                window.htmx.process(context);
                                            } catch (e) {
                                                console.error('AuthHandler: Error processing HTMX', e);
                                            }
                                        }
                                    }
                                };


                                // Private utility functions
                                const utils = {
                                    // Safe element selection
                                    safeQuerySelector: function(selector, context = document) {
                                        try {
                                            return context.querySelector(selector);
                                        } catch (e) {
                                            console.warn(`AuthHandler: Invalid selector "${selector}"`, e);
                                            return null;
                                        }
                                    },

                                    // Safe element selection (multiple)
                                    safeQuerySelectorAll: function(selector, context = document) {
                                        try {
                                            return Array.from(context.querySelectorAll(selector));
                                        } catch (e) {
                                            console.warn(`AuthHandler: Invalid selector "${selector}"`, e);
                                            return [];
                                        }
                                    },

                                    // Create element with attributes
                                    createElement: function(tag, attributes = {}, innerHTML = '') {
                                        const element = document.createElement(tag);

                                        Object.keys(attributes).forEach(key => {
                                            if (key === 'className') {
                                                element.className = attributes[key];
                                            } else if (key === 'style' && typeof attributes[key] === 'object') {
                                                Object.assign(element.style, attributes[key]);
                                            } else {
                                                element.setAttribute(key, attributes[key]);
                                            }
                                        });

                                        if (innerHTML) {
                                            element.innerHTML = innerHTML;
                                        }

                                        return element;
                                    },

                                    // Debounce function to prevent rapid calls
                                    debounce: function(func, wait) {
                                        let timeout;
                                        return function executedFunction(...args) {
                                            const later = () => {
                                                clearTimeout(timeout);
                                                func(...args);
                                            };
                                            clearTimeout(timeout);
                                            timeout = setTimeout(later, wait);
                                        };
                                    }
                                };

                                // Loader management
                                const loader = {
                                    show: function() {
                                        if (!container) {
                                            console.warn('AuthHandler: Container not found for loader');
                                            return;
                                        }

                                        // Prevent multiple loaders
                                        if (utils.safeQuerySelector(`#${CONFIG.loaderOverlayId}`)) {
                                            return;
                                        }

                                        const loaderElement = utils.createElement('div', {
                                            id: CONFIG.loaderOverlayId,
                                            className: 'position-absolute top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center bg-white',
                                            style: { zIndex: CONFIG.zIndex }
                                        }, `
                <div class="text-center">
                    <div class="spinner-border text-primary mb-3" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="text-muted">Processing...</p>
                </div>
            `);

                                        container.appendChild(loaderElement);
                                    },

                                    hide: function() {
                                        const loaderElement = utils.safeQuerySelector(`#${CONFIG.loaderOverlayId}`);
                                        if (loaderElement && loaderElement.parentNode) {
                                            loaderElement.parentNode.removeChild(loaderElement);
                                        }
                                    }
                                };

                                // Error handling
                                const errorHandler = {
                                    show: function(message) {
                                        if (!container) {
                                            console.error('AuthHandler: Container not found for error display');
                                            return;
                                        }

                                        const alertElement = utils.createElement('div', {
                                            className: 'alert alert-danger alert-dismissible fade show m-2',
                                            role: 'alert'
                                        }, `
                <strong>Error:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `);

                                        container.insertBefore(alertElement, container.firstChild);

                                        // Auto-remove after 5 seconds
                                        setTimeout(() => {
                                            if (alertElement && alertElement.parentNode) {
                                                alertElement.parentNode.removeChild(alertElement);
                                            }
                                        }, 5000);
                                    }
                                };

                                // Password toggle functionality
                                const passwordToggle = {
                                    icons: {
                                        show: `
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5"
                    fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477
                        0 8.268 2.943 9.542 7-1.274 4.057-5.065
                        7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
            `,
                                        hide: `
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5"
                    fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M13.875 18.825A10.05 10.05 0 0112 19c-4.477
                        0-8.268-2.943-9.542-7a9.97 9.97 0
                        012.845-4.419m3.181-2.104A9.956 9.956
                        0 0112 5c4.477 0 8.268 2.943
                        9.542 7a9.969 9.969 0 01-4.043
                        5.197M15 12a3 3 0 11-6 0 3
                        3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M3 3l18 18" />
                </svg>
            `
                                    },

                                    init: function(context) {
                                        if (!context) return;

                                        const toggleButtons = utils.safeQuerySelectorAll(
                                            "button[aria-label='Show password'], button[aria-label='Hide password']",
                                            context
                                        );

                                        toggleButtons.forEach(btn => {
                                            if (btn.dataset.authToggleBound) {
                                                return; // Already initialized
                                            }

                                            const inputId = btn.getAttribute('aria-controls');
                                            const input = inputId ? utils.safeQuerySelector(`#${inputId}`, context) : null;

                                            if (!input) {
                                                console.warn('AuthHandler: Password input not found for toggle button');
                                                return;
                                            }

                                            // Set initial state
                                            btn.innerHTML = this.icons.show;

                                            // Create toggle handler
                                            const toggleHandler = () => {
                                                try {
                                                    if (input.type === 'password') {
                                                        input.type = 'text';
                                                        btn.setAttribute('aria-label', 'Hide password');
                                                        btn.innerHTML = this.icons.hide;
                                                    } else {
                                                        input.type = 'password';
                                                        btn.setAttribute('aria-label', 'Show password');
                                                        btn.innerHTML = this.icons.show;
                                                    }
                                                } catch (e) {
                                                    console.error('AuthHandler: Error toggling password visibility', e);
                                                }
                                            };

                                            // Remove existing listeners to prevent duplicates
                                            btn.removeEventListener('click', btn._authToggleHandler);

                                            // Add new listener
                                            btn.addEventListener('click', toggleHandler);
                                            btn._authToggleHandler = toggleHandler;

                                            // Mark as initialized
                                            btn.dataset.authToggleBound = 'true';
                                        });
                                    }
                                };


                                // Event handlers
                                const eventHandlers = {
                                    beforeRequest: function() {
                                        loader.show();
                                    },

                                    afterSwap: function(event) {
                                        loader.hide();

                                        if (event.target && event.target.id === CONFIG.containerId) {
                                            htmxIntegration.processContent(event.target);
                                        }
                                    },

                                    responseError: function(event) {
                                        loader.hide();
                                        const message = (event.detail && event.detail.xhr && event.detail.xhr.statusText) ||
                                            'Something went wrong. Please try again.';
                                        errorHandler.show(message);
                                    },

                                    sendError: function() {
                                        loader.hide();
                                        errorHandler.show('Network error. Please check your connection.');
                                    }
                                };

                                // Initialization
                                const init = function() {
                                    if (isInitialized) {
                                        console.warn('AuthHandler: Already initialized');
                                        return false;
                                    }

                                    container = utils.safeQuerySelector(`#${CONFIG.containerId}`);
                                    if (!container) {
                                        console.error(`AuthHandler: Container with id "${CONFIG.containerId}" not found`);
                                        return false;
                                    }

                                    // Set up HTMX event listeners
                                    const eventMappings = [
                                        ['htmx:beforeRequest', eventHandlers.beforeRequest],
                                        ['htmx:afterSwap', eventHandlers.afterSwap],
                                        ['htmx:responseError', eventHandlers.responseError],
                                        ['htmx:sendError', eventHandlers.sendError]
                                    ];

                                    eventMappings.forEach(([eventName, handler]) => {
                                        // Remove existing listeners to prevent duplicates
                                        document.body.removeEventListener(eventName, handler);
                                        // Add new listener
                                        document.body.addEventListener(eventName, handler);
                                    });

                                    // Initial content processing
                                    htmxIntegration.processContent(container);

                                    isInitialized = true;
                                    console.log('AuthHandler: Initialized successfully');
                                    return true;
                                };

                                // Cleanup function
                                const destroy = function() {
                                    if (!isInitialized) return;

                                    const eventMappings = [
                                        ['htmx:beforeRequest', eventHandlers.beforeRequest],
                                        ['htmx:afterSwap', eventHandlers.afterSwap],
                                        ['htmx:responseError', eventHandlers.responseError],
                                        ['htmx:sendError', eventHandlers.sendError]
                                    ];

                                    eventMappings.forEach(([eventName, handler]) => {
                                        document.body.removeEventListener(eventName, handler);
                                    });

                                    loader.hide();
                                    isInitialized = false;
                                    container = null;

                                    console.log('AuthHandler: Destroyed successfully');
                                };

                                // Public API
                                return {
                                    init: init,
                                    destroy: destroy,
                                    isInitialized: function() { return isInitialized; },

                                    // Utility methods that can be used externally
                                    showLoader: loader.show,
                                    hideLoader: loader.hide,
                                    showError: errorHandler.show,

                                    // Manual content processing
                                    processContent: htmxIntegration.processContent,

                                    // Configuration access
                                    getConfig: function() { return Object.assign({}, CONFIG); },
                                    setConfig: function(newConfig) {
                                        if (isInitialized) {
                                            console.warn('AuthHandler: Cannot change configuration after initialization');
                                            return false;
                                        }
                                        Object.assign(CONFIG, newConfig);
                                        return true;
                                    }
                                };
                            })();

                            // Auto-initialize when DOM is ready
                            (function() {
                                if (document.readyState === 'loading') {
                                    document.addEventListener('DOMContentLoaded', function() {
                                        AuthHandler.init();
                                    });
                                } else {
                                    // DOM is already ready
                                    AuthHandler.init();
                                }
                            })();
                    </script>
```


---
### Stop here setup is done
---


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
