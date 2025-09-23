/**
 * PasswordValidator - Handles password visibility toggle and confirmation validation
 */
class PasswordValidator {
    constructor(options = {}) {
        this.options = {
            passwordInputId: 'password',
            confirmPasswordInputId: 'password-confirm',
            toggleButtonSelector: '[data-password-toggle]',
            errorContainerPrefix: 'input-error-container-',
            showIcon: 'fa-eye fas',
            hideIcon: 'fa-eye-slash fas',
            errorColor: 'hsl(0 84.2% 60.2%)',
            successColor: 'hsl(142.1 76.2% 36.3%)',
            shakeAnimationDuration: 500,
            ...options
        };

        this.passwordInput = null;
        this.confirmPasswordInput = null;
        this.toggleButton = null;
        this.isInitialized = false;
        this.observers = [];

        this.init();
    }

    init() {
        this._setupMutationObserver();
        this._initializeElements();
        this._injectStyles();
    }

    _initializeElements() {
        this.passwordInput = this._getElementById(this.options.passwordInputId);
        this.confirmPasswordInput = this._getElementById(this.options.confirmPasswordInputId);
        this.toggleButton = document.querySelector(this.options.toggleButtonSelector);

        if (this.passwordInput) {
            this._initializePasswordToggle();
        }

        if (this.passwordInput && this.confirmPasswordInput) {
            this._initializePasswordConfirmation();
        }

        this.isInitialized = true;
    }

    _getElementById(id) {
        if (!id) return null;

        // Handle various ID formats
        const cleanId = id.replace(/^#/, ''); // Remove leading # if present
        const element = document.getElementById(cleanId);

        if (!element) {
            // Try alternative selectors
            const alternatives = [
                `[id="${cleanId}"]`,
                `[name="${cleanId}"]`,
                `input[type="password"][id*="${cleanId}"]`
            ];

            for (const selector of alternatives) {
                const found = document.querySelector(selector);
                if (found) return found;
            }
        }

        return element;
    }

    _initializePasswordToggle() {
        if (!this.toggleButton || !this.passwordInput) return;

        // Remove existing listeners to prevent duplicates
        this._cloneButton();

        this.toggleButton.addEventListener('click', this._handleToggleClick.bind(this));
        this.toggleButton.addEventListener('keydown', this._handleToggleKeydown.bind(this));

        // Set initial state
        this._updateToggleState(false);
    }

    _cloneButton() {
        if (!this.toggleButton) return;

        const newButton = this.toggleButton.cloneNode(true);
        this.toggleButton.parentNode.replaceChild(newButton, this.toggleButton);
        this.toggleButton = newButton;
    }

    _handleToggleClick(event) {
        event.preventDefault();
        event.stopPropagation();

        if (!this.passwordInput) return;

        const isCurrentlyVisible = this.passwordInput.type === 'text';
        this.passwordInput.type = isCurrentlyVisible ? 'password' : 'text';

        this._updateToggleState(!isCurrentlyVisible);
        this.passwordInput.focus();
    }

    _handleToggleKeydown(event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            this._handleToggleClick(event);
        }
    }

    _updateToggleState(isVisible) {
        if (!this.toggleButton) return;

        this.toggleButton.classList.toggle('password-visible', isVisible);
        this.toggleButton.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');

        const icon = this.toggleButton.querySelector('i');
        if (icon) {
            icon.className = isVisible ? this.options.hideIcon : this.options.showIcon;
        }
    }

    _initializePasswordConfirmation() {
        if (!this.confirmPasswordInput || !this.passwordInput) return;

        // Add event listeners
        this.confirmPasswordInput.addEventListener('input', this._validatePasswordMatch.bind(this));
        this.confirmPasswordInput.addEventListener('blur', this._validatePasswordMatch.bind(this));

        this.passwordInput.addEventListener('input', () => {
            if (this.confirmPasswordInput && this.confirmPasswordInput.value) {
                this._validatePasswordMatch();
            }
        });

        // Add form submit validation
        const form = this.passwordInput.closest('form');
        if (form) {
            form.addEventListener('submit', this._handleFormSubmit.bind(this));
        }
    }

    _validatePasswordMatch() {
        if (!this.passwordInput || !this.confirmPasswordInput) return true;

        const password = this.passwordInput.value;
        const confirmPassword = this.confirmPasswordInput.value;
        const errorContainer = this._getOrCreateErrorContainer();

        if (confirmPassword && password !== confirmPassword) {
            this._showValidationError(errorContainer, 'Passwords do not match');
            return false;
        } else if (confirmPassword && password === confirmPassword) {
            this._showValidationSuccess(errorContainer, 'Passwords match');
            return true;
        } else {
            this._clearValidation(errorContainer);
            return true;
        }
    }

    _getOrCreateErrorContainer() {
        if (!this.confirmPasswordInput) return null;

        const containerId = `${this.options.errorContainerPrefix}${this.options.confirmPasswordInputId}`;
        let container = document.getElementById(containerId);

        if (!container) {
            container = document.createElement('div');
            container.id = containerId;
            container.className = 'error-container';
            container.style.marginTop = '0.375rem';
            this.confirmPasswordInput.parentNode.appendChild(container);
        }

        return container;
    }

    _showValidationError(container, message) {
        if (!container || !this.confirmPasswordInput) return;

        this.confirmPasswordInput.setAttribute('aria-invalid', 'true');
        this.confirmPasswordInput.classList.add('error');

        container.innerHTML = `<div class="error-message" style="color: ${this.options.errorColor}; font-size: 0.875rem; font-weight: 500;">${message}</div>`;
        container.style.display = 'block';
    }

    _showValidationSuccess(container, message) {
        if (!container || !this.confirmPasswordInput) return;

        this.confirmPasswordInput.setAttribute('aria-invalid', 'false');
        this.confirmPasswordInput.classList.remove('error');

        container.innerHTML = `<div class="success-message" style="color: ${this.options.successColor}; font-size: 0.875rem; font-weight: 500;">${message}</div>`;
        container.style.display = 'block';
    }

    _clearValidation(container) {
        if (!container || !this.confirmPasswordInput) return;

        this.confirmPasswordInput.setAttribute('aria-invalid', 'false');
        this.confirmPasswordInput.classList.remove('error');
        container.innerHTML = '';
        container.style.display = 'none';
    }

    _handleFormSubmit(event) {
        if (!this.confirmPasswordInput || !this.confirmPasswordInput.value) return;

        if (!this._validatePasswordMatch()) {
            event.preventDefault();
            this.confirmPasswordInput.focus();
            this._shakeErrorContainer();
            return false;
        }
        return true;
    }

    _shakeErrorContainer() {
        const container = this._getOrCreateErrorContainer();
        if (!container) return;

        container.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
            container.style.animation = '';
        }, this.options.shakeAnimationDuration);
    }

    _setupMutationObserver() {
        if (typeof MutationObserver === 'undefined') return;

        const observer = new MutationObserver((mutations) => {
            let shouldReinit = false;

            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    const addedNodes = Array.from(mutation.addedNodes);
                    const hasRelevantElements = addedNodes.some(node =>
                        node.nodeType === Node.ELEMENT_NODE &&
                        node.querySelector &&
                        (node.querySelector(this.options.toggleButtonSelector) ||
                            node.querySelector(`#${this.options.passwordInputId}`) ||
                            node.querySelector(`#${this.options.confirmPasswordInputId}`))
                    );

                    if (hasRelevantElements) {
                        shouldReinit = true;
                    }
                }
            });

            if (shouldReinit) {
                setTimeout(() => this._initializeElements(), 100);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        this.observers.push(observer);
    }

    _injectStyles() {
        if (document.querySelector('#password-validation-styles')) return;

        const styles = `
            .error-container {
                margin-top: 0.375rem;
            }

            .error-message {
                color: ${this.options.errorColor};
                font-size: 0.875rem;
                font-weight: 500;
            }

            .success-message {
                color: ${this.options.successColor};
                font-size: 0.875rem;
                font-weight: 500;
            }

            input.error,
            input[aria-invalid="true"] {
                border-color: ${this.options.errorColor} !important;
            }

            input.error:focus,
            input[aria-invalid="true"]:focus {
                border-color: ${this.options.errorColor} !important;
                box-shadow: 0 0 0 2px ${this.options.errorColor.replace(')', ' / 0.2)')} !important;
            }

            .pf-v5-c-input-group:has(input.error),
            .pf-v5-c-input-group:has(input[aria-invalid="true"]) {
                border-color: ${this.options.errorColor} !important;
            }

            .pf-v5-c-input-group:has(input.error):focus-within,
            .pf-v5-c-input-group:has(input[aria-invalid="true"]):focus-within {
                border-color: ${this.options.errorColor} !important;
                box-shadow: 0 0 0 2px ${this.options.errorColor.replace(')', ' / 0.2)')} !important;
            }

            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
        `;

        const styleSheet = document.createElement('style');
        styleSheet.id = 'password-validation-styles';
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
    }

    destroy() {
        this.observers.forEach(observer => observer.disconnect());
        this.observers = [];
        this.isInitialized = false;
    }

    reinitialize() {
        this._initializeElements();
    }

    // Public methods for manual validation
    validatePasswords() {
        return this._validatePasswordMatch();
    }

    clearValidation() {
        const container = this._getOrCreateErrorContainer();
        this._clearValidation(container);
    }
}

export default PasswordValidator;