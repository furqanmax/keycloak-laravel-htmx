<?php

namespace KeycloakAuth\Laravel\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Route;
use KeycloakAuth\Laravel\Services\KeycloakService;
use KeycloakAuth\Laravel\Services\KeycloakProxyService;
use KeycloakAuth\Laravel\Http\Middleware\KeycloakAuthenticate;
use KeycloakAuth\Laravel\Http\Middleware\KeycloakGuest;

class KeycloakAuthServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge config
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/keycloak.php',
            'keycloak'
        );

        // Register KeycloakService as singleton
        $this->app->singleton(KeycloakService::class, function ($app) {
            return new KeycloakService(
                config('keycloak.base_url'),
                config('keycloak.realm'),
                config('keycloak.client_id'),
                config('keycloak.client_secret'),
                config('keycloak.redirect_uri')
            );
        });

        // Register KeycloakProxyService
        $this->app->singleton(KeycloakProxyService::class, function ($app) {
            return new KeycloakProxyService($app->make(KeycloakService::class));
        });

        // Register facade accessor
        $this->app->bind('keycloak-auth', function ($app) {
            return $app->make(KeycloakService::class);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publish config
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/keycloak.php' => config_path('keycloak.php'),
            ], 'keycloak-config');

            // Publish views
            $this->publishes([
                __DIR__ . '/../../resources/views' => resource_path('views/vendor/keycloak-auth'),
            ], 'keycloak-views');
            $this->publishes([
                __DIR__.'/../../resources/css' => public_path('vendor/keycloak-auth/css'),
//                __DIR__.'/../../resources/js' => public_path('vendor/keycloak-auth/js'),
            ], 'public');
        }

        // Load views
        $this->loadViewsFrom(__DIR__ . '/../../resources/views', 'keycloak-auth');

        // Load routes
        $this->loadRoutesFrom(__DIR__ . '/../../routes/web.php');

        // Register middleware
        $router = $this->app['router'];
        $router->aliasMiddleware('keycloak.auth', KeycloakAuthenticate::class);
        $router->aliasMiddleware('keycloak.guest', KeycloakGuest::class);

        // Register Blade directives
        $this->registerBladeDirectives();
    }

    /**
     * Register Blade directives for Keycloak authentication.
     */
    protected function registerBladeDirectives(): void
    {
        \Blade::if('keycloak', function () {
            return session()->has('keycloak_token');
        });

        \Blade::directive('keycloakUser', function () {
            return "<?php echo session('keycloak_user') ? json_encode(session('keycloak_user')) : 'null'; ?>";
        });

        \Blade::directive('keycloakLoginUrl', function () {
            return "<?php echo route('keycloak.login'); ?>";
        });

        \Blade::directive('keycloakLogoutUrl', function () {
            return "<?php echo route('keycloak.logout'); ?>";
        });
    }
}
