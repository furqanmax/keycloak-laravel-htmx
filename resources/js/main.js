/**
 * Main application initialization
 * Usage example and setup
 */

import KeycloakProxy from './KeycloakProxy.js';
import PasswordValidator from './PasswordValidator.js';

class KeycloakApp {
    constructor(config = {}) {
        this.config = {
            containerId: 'kc-container',
            proxyRoute: '/keycloak/proxy', // This should be replaced with actual route
            passwordInputId: 'password',
            confirmPasswordInputId: 'password-confirm',
            ...config
        };

        this.keycloakProxy = null;
        this.passwordValidator = null;
        this.isInitialized = false;

        this.init();
    }

    init() {
        if (this.isInitialized) return;

        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this._initialize());
        } else {
            this._initialize();
        }
    }

    _initialize() {
        try {
            // Initialize Keycloak Proxy
            this.keycloakProxy = new KeycloakProxy(
                this.config.containerId,
                this.config.proxyRoute,
                {
                    loaderZIndex: '1050',
                    errorDismissTime: 5000
                }
            );

            // Initialize Password Validator
            this.passwordValidator = new PasswordValidator({
                passwordInputId: this.config.passwordInputId,
                confirmPasswordInputId: this.config.confirmPasswordInputId,
                toggleButtonSelector: '[data-password-toggle]',
                errorContainerPrefix: 'input-error-container-'
            });

            // Setup HTMX integration if available
            this._setupHtmxIntegration();

            this.isInitialized = true;
            console.log('KeycloakApp initialized successfully');

        } catch (error) {
            console.error('Failed to initialize KeycloakApp:', error);
        }
    }

    _setupHtmxIntegration() {
        if (typeof htmx === 'undefined') {
            console.warn('HTMX not found. Some features may not work properly.');
            return;
        }

        // Reinitialize password validator after HTMX swaps
        document.addEventListener('htmx:afterSwap', (event) => {
            if (event.target.id === this.config.containerId) {
                setTimeout(() => {
                    if (this.passwordValidator) {
                        this.passwordValidator.reinitialize();
                    }
                }, 100);
            }
        });
    }

    // Public API methods
    reloadKeycloak() {
        if (this.keycloakProxy) {
            this.keycloakProxy.reload();
        }
    }

    validatePasswords() {
        if (this.passwordValidator) {
            return this.passwordValidator.validatePasswords();
        }
        return true;
    }

    clearPasswordValidation() {
        if (this.passwordValidator) {
            this.passwordValidator.clearValidation();
        }
    }

    destroy() {
        if (this.keycloakProxy) {
            this.keycloakProxy.destroy();
        }
        if (this.passwordValidator) {
            this.passwordValidator.destroy();
        }
        this.isInitialized = false;
    }
}

// Auto-initialize with default configuration
// You can customize this based on your needs
const app = new KeycloakApp({
    containerId: 'kc-container',
    proxyRoute: '{{ route("keycloak.proxy") }}', // Replace with actual route
    passwordInputId: 'password',
    confirmPasswordInputId: 'password-confirm'
});

// Export for manual initialization if needed
export default KeycloakApp;

// Make available globally if not using modules
if (typeof window !== 'undefined') {
    window.KeycloakApp = KeycloakApp;
    window.KeycloakProxy = KeycloakProxy;
    window.PasswordValidator = PasswordValidator;
}