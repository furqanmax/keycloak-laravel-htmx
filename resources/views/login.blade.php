<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ config('keycloak.ui.brand_name') }} - Login</title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">

    @if(config('keycloak.ui.custom_css'))
        <link rel="stylesheet" href="{{ config('keycloak.ui.custom_css') }}">
    @endif

    <!-- HTMX -->
    <script src="https://unpkg.com/htmx.org@1.9.12" defer></script>

    <style>
        .hero-section { min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .hero-left { padding: 3rem; color: white; }
        .hero-right { background: white; padding: 2rem; min-height: 100vh; display: flex; align-items: center; }
        .auth-container { width: 100%; max-width: 450px; margin: 0 auto; }
        .kc-container { min-height: 400px; }
        .feature-item { margin-bottom: 1.5rem; }
        .spinner-border { width: 1.5rem; height: 1.5rem; }
    </style>
</head>
<body>
    <!-- Hero Section with Embedded Authentication -->
    <section class="hero-section">
        <div class="container-fluid h-100">
            <div class="row h-100">
                <!-- Left Side - Branding and Information -->
                <div class="col-lg-7 hero-left d-flex align-items-center">
                    <div class="hero-content">
                        @if(config('keycloak.ui.brand_logo'))
                            <img src="{{ config('keycloak.ui.brand_logo') }}" alt="Logo" class="mb-4" style="max-height: 60px;">
                        @endif

                        <h1 class="display-3 fw-bold mb-4">{{ config('keycloak.ui.hero.title', 'Secure Authentication') }}</h1>
                        <p class="lead mb-4">{{ config('keycloak.ui.hero.subtitle', 'Powered by Keycloak SSO') }}</p>

                        @if(config('keycloak.ui.hero.show_features'))
                        <div class="features mt-5">
                            <div class="feature-item d-flex">
                                <i class="bi bi-shield-check fs-4 me-3"></i>
                                <div>
                                    <h6 class="mb-1">Enterprise Security</h6>
                                    <p class="small mb-0 opacity-75">Industry-standard OAuth 2.0 and OpenID Connect protocols</p>
                                </div>
                            </div>
                            <div class="feature-item d-flex">
                                <i class="bi bi-person-check fs-4 me-3"></i>
                                <div>
                                    <h6 class="mb-1">Single Sign-On</h6>
                                    <p class="small mb-0 opacity-75">One login for all your applications</p>
                                </div>
                            </div>
                            <div class="feature-item d-flex">
                                <i class="bi bi-globe fs-4 me-3"></i>
                                <div>
                                    <h6 class="mb-1">Social Login</h6>
                                    <p class="small mb-0 opacity-75">Connect with your favorite social accounts</p>
                                </div>
                            </div>
                        </div>
                        @endif
                    </div>
                </div>

                <!-- Right Side - Authentication Form (HTMX) -->
                <div class="col-lg-5 hero-right">
                    <div class="auth-container">
                        @if(session('error'))
                            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                {{ session('error') }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        @endif

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
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Bootstrap Bundle with Popper -->
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
                    // Check if this is a social login link (contains broker or social provider)
                    if (href.includes('/broker/') || href.includes('kc_idp_hint=')) {
                        // For social login, keep as regular link but intercept click
                        a.addEventListener('click', function(e) {
                            e.preventDefault();
                            // Store current state in session storage
                            sessionStorage.setItem('keycloak_return', window.location.href);
                            
                            // Extract provider from URL
                            let provider = '';
                            if (href.includes('/broker/google/')) provider = 'google';
                            else if (href.includes('/broker/facebook/')) provider = 'facebook';
                            else if (href.includes('/broker/github/')) provider = 'github';
                            else if (href.includes('kc_idp_hint=google')) provider = 'google';
                            else if (href.includes('kc_idp_hint=facebook')) provider = 'facebook';
                            else if (href.includes('kc_idp_hint=github')) provider = 'github';
                            
                            if (provider) {
                                // Use our dedicated social login route
                                window.location.href = `{{ route('keycloak.social', '') }}/${provider}`;
                            } else {
                                // Fallback to direct link
                                window.location.href = href;
                            }
                        });
                    } else {
                        // Regular Keycloak links - use HTMX
                        a.setAttribute('hx-get', `{{ route('keycloak.proxy') }}?url=${encodeURIComponent(href)}`);
                        a.setAttribute('hx-target', '#kc-container');
                        a.setAttribute('hx-swap', 'innerHTML');
                        a.removeAttribute('href');
                    }
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
        
        // Handle redirect from social login
        document.addEventListener('DOMContentLoaded', function() {
            // Check if we're returning from social login
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('code') || urlParams.has('error')) {
                // Load the Keycloak container with the callback
                const container = document.getElementById('kc-container');
                if (container) {
                    htmx.ajax('GET', `{{ route('keycloak.proxy') }}?url=${encodeURIComponent(window.location.href)}`, '#kc-container');
                }
            }
        });
    })();
    </script>
</body>
</html>
