/**
 * KeycloakProxy - Handles HTMX-based Keycloak integration with dynamic content loading
 */
class KeycloakProxy {
    constructor(containerId, proxyRoute, options = {}) {
        this.containerId = containerId;
        this.proxyRoute = proxyRoute;
        this.options = {
            loaderZIndex: '1050',
            errorDismissTime: 5000,
            ...options
        };

        this.container = null;
        this.isInitialized = false;

        this.init();
    }

    init() {
        if (this.isInitialized) return;

        this.container = this._getContainer();
        if (!this.container) {
            console.error(`KeycloakProxy: Container with ID '${this.containerId}' not found`);
            return;
        }

        this._bindEvents();
        this.isInitialized = true;
    }

    _getContainer() {
        return document.getElementById(this.containerId);
    }

    _createLoader() {
        if (document.getElementById("kc-loader-overlay")) return;

        const loader = document.createElement("div");
        loader.id = "kc-loader-overlay";
        loader.className = "position-absolute top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center bg-white";
        loader.style.zIndex = this.options.loaderZIndex;
        loader.innerHTML = `
            <div class="text-center">
                <div class="spinner-border text-primary mb-3" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="text-muted">Processing...</p>
            </div>
        `;

        this.container.appendChild(loader);
    }

    _removeLoader() {
        const loader = document.getElementById("kc-loader-overlay");
        if (loader) loader.remove();
    }

    _showError(message) {
        const alert = document.createElement("div");
        alert.className = "alert alert-danger alert-dismissible fade show m-2";
        alert.role = "alert";
        alert.innerHTML = `
            <strong>Error:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        this.container.prepend(alert);

        // Auto-dismiss after specified time
        if (this.options.errorDismissTime > 0) {
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, this.options.errorDismissTime);
        }
    }

    _rewireLinks(container) {
        const links = container.querySelectorAll("a[href]");
        links.forEach(link => {
            const href = link.getAttribute("href");
            if (href && !href.startsWith("javascript:") && !href.startsWith("#")) {
                link.setAttribute("hx-get", `${this.proxyRoute}?url=${encodeURIComponent(href)}`);
                link.setAttribute("hx-target", `#${this.containerId}`);
                link.setAttribute("hx-swap", "innerHTML");
                link.removeAttribute("href");
            }
        });
    }

    _rewireForms(container) {
        const forms = container.querySelectorAll("form[action]");
        forms.forEach(form => {
            const action = form.getAttribute("action");
            const method = (form.getAttribute("method") || "GET").toUpperCase();

            if (action) {
                const htmxAttribute = method === "POST" ? "hx-post" : "hx-get";
                form.setAttribute(htmxAttribute, `${this.proxyRoute}?url=${encodeURIComponent(action)}`);
                form.setAttribute("hx-target", `#${this.containerId}`);
                form.setAttribute("hx-swap", "innerHTML");
                form.removeAttribute("action");
            }
        });
    }

    _processContainer(container) {
        this._rewireLinks(container);
        this._rewireForms(container);

        // Re-process with HTMX if available
        if (typeof htmx !== 'undefined') {
            htmx.process(container);
        }
    }

    _bindEvents() {
        // HTMX event handlers
        document.body.addEventListener("htmx:beforeRequest", (event) => {
            if (this._isTargetingContainer(event)) {
                this._createLoader();
                // Ensure cookies are included in HTMX requests
                this._ensureCookiesInRequest(event);
            }
        });

        document.body.addEventListener("htmx:afterSwap", (event) => {
            if (this._isTargetingContainer(event)) {
                this._removeLoader();
                this._processContainer(event.target);
            }
        });

        document.body.addEventListener("htmx:responseError", (event) => {
            if (this._isTargetingContainer(event)) {
                this._removeLoader();
                const message = event.detail?.xhr?.statusText || "Something went wrong. Please try again.";
                this._showError(message);
            }
        });

        document.body.addEventListener("htmx:sendError", (event) => {
            if (this._isTargetingContainer(event)) {
                this._removeLoader();
                this._showError("Network error. Please check your connection.");
            }
        });
    }

    _isTargetingContainer(event) {
        return event.target && event.target.id === this.containerId;
    }
    
    _ensureCookiesInRequest(event) {
        // Ensure HTMX includes credentials (cookies) in requests
        if (event.detail && event.detail.xhr) {
            event.detail.xhr.withCredentials = true;
        }
        
        // Add custom headers if needed
        if (!event.detail.headers) {
            event.detail.headers = {};
        }
        
        // Ensure credentials are included
        event.detail.headers['X-Requested-With'] = 'XMLHttpRequest';
        
        // Get any preserved Keycloak cookies from sessionStorage
        const preservedCookies = sessionStorage.getItem('keycloak_cookies');
        if (preservedCookies) {
            event.detail.headers['X-Keycloak-Cookies'] = preservedCookies;
        }
    }

    destroy() {
        this._removeLoader();
        this.isInitialized = false;
        // Note: HTMX events are on document.body, so they persist beyond this instance
    }

    reload() {
        if (this.container && typeof htmx !== 'undefined') {
            htmx.trigger(this.container, 'load');
        }
    }
}

export default KeycloakProxy;