/**
 * Open Bastion LightDM Webkit Greeter
 *
 * This greeter supports two authentication modes:
 * 1. SSO Mode: Uses iframe to authenticate via LLNG portal
 * 2. Offline Mode: Uses cached credentials for local authentication
 *
 * The greeter communicates with lightdm-webkit2-greeter via the
 * global `lightdm` object.
 */

(function() {
    'use strict';

    // Configuration - can be overridden via /etc/lightdm/lightdm-openbastion.conf
    const CONFIG = {
        portalUrl: 'https://auth.example.com',  // LLNG portal URL
        desktopLoginPath: '/desktop/login',     // Desktop login endpoint
        checkOnlineInterval: 30000,             // Check online status every 30s
        onlineCheckTimeout: 5000,               // Timeout for online check
        clockUpdateInterval: 1000,              // Update clock every second
        sessionStorageKey: 'ob_selected_session',
        offlineRetryInterval: 60000,            // Retry online check every 60s when offline
        maxOfflineCheckRetries: 3,              // Number of failed checks before switching to offline
        debug: false                            // Enable debug logging (set via greeter config)
    };

    // Gated debug logger - avoids leaking sensitive data in production
    function debugLog() {
        if (CONFIG.debug) {
            console.log.apply(console, arguments);
        }
    }

    // State
    let isOnline = true;
    let currentMode = 'sso';  // 'sso' or 'offline'
    let selectedSession = null;
    let selectedUser = null;
    let authToken = null;
    let pendingPassword = null;  // Closure-scoped, not global

    // DOM Elements
    const elements = {
        hostname: document.getElementById('hostname'),
        ssoMode: document.getElementById('sso-mode'),
        offlineMode: document.getElementById('offline-mode'),
        ssoIframe: document.getElementById('sso-iframe'),
        iframeLoading: document.getElementById('iframe-loading'),
        offlineForm: document.getElementById('offline-form'),
        username: document.getElementById('username'),
        password: document.getElementById('password'),
        loginBtn: document.getElementById('login-btn'),
        toggleMode: document.getElementById('toggle-mode'),
        toggleText: document.getElementById('toggle-text'),
        errorMessage: document.getElementById('error-message'),
        sessionSelect: document.getElementById('session'),
        clockTime: document.getElementById('clock-time'),
        clockDate: document.getElementById('clock-date'),
        btnShutdown: document.getElementById('btn-shutdown'),
        btnRestart: document.getElementById('btn-restart'),
        btnSuspend: document.getElementById('btn-suspend')
    };

    /**
     * Initialize the greeter
     */
    function init() {
        debugLog('Initializing Open Bastion Greeter');

        // Load configuration from lightdm config if available
        loadConfig();

        // Set hostname
        if (typeof lightdm !== 'undefined' && lightdm.hostname) {
            elements.hostname.textContent = lightdm.hostname;
        }

        // Initialize sessions dropdown
        initSessions();

        // Initialize system controls
        initSystemControls();

        // Start clock
        updateClock();
        setInterval(updateClock, CONFIG.clockUpdateInterval);

        // Check online status
        checkOnlineStatus();
        setInterval(checkOnlineStatus, CONFIG.checkOnlineInterval);

        // Setup event listeners
        setupEventListeners();

        // Initialize SSO iframe
        if (isOnline) {
            initSSOIframe();
        } else {
            switchMode('offline');
        }

        debugLog('Greeter initialized');
    }

    /**
     * Load configuration from LightDM config file
     */
    function loadConfig() {
        // Try to get config from greeter_config
        if (typeof greeter_config !== 'undefined') {
            if (greeter_config.portal_url) {
                CONFIG.portalUrl = greeter_config.portal_url;
            }
            if (greeter_config.desktop_login_path) {
                CONFIG.desktopLoginPath = greeter_config.desktop_login_path;
            }
        }

        // Also check for embedded config in index.html
        const configScript = document.getElementById('greeter-config');
        if (configScript) {
            try {
                const config = JSON.parse(configScript.textContent);
                Object.assign(CONFIG, config);
            } catch (e) {
                console.warn('Failed to parse embedded config:', e);
            }
        }

        debugLog('Loaded config:', CONFIG);
    }

    /**
     * Initialize available sessions
     */
    function initSessions() {
        if (typeof lightdm === 'undefined' || !lightdm.sessions) {
            console.warn('LightDM sessions not available');
            return;
        }

        // Clear existing options
        elements.sessionSelect.innerHTML = '';

        // Add sessions
        lightdm.sessions.forEach(function(session) {
            const option = document.createElement('option');
            option.value = session.key;
            option.textContent = session.name;
            elements.sessionSelect.appendChild(option);
        });

        // Restore last selected session
        const savedSession = localStorage.getItem(CONFIG.sessionStorageKey);
        if (savedSession) {
            elements.sessionSelect.value = savedSession;
        }

        // Set default session
        selectedSession = elements.sessionSelect.value || lightdm.default_session;

        // Save selection on change
        elements.sessionSelect.addEventListener('change', function() {
            selectedSession = this.value;
            localStorage.setItem(CONFIG.sessionStorageKey, selectedSession);
        });
    }

    /**
     * Initialize system control buttons
     */
    function initSystemControls() {
        if (typeof lightdm === 'undefined') {
            console.warn('LightDM not available');
            return;
        }

        // Shutdown
        if (lightdm.can_shutdown) {
            elements.btnShutdown.addEventListener('click', function() {
                lightdm.shutdown();
            });
        } else {
            elements.btnShutdown.style.display = 'none';
        }

        // Restart
        if (lightdm.can_restart) {
            elements.btnRestart.addEventListener('click', function() {
                lightdm.restart();
            });
        } else {
            elements.btnRestart.style.display = 'none';
        }

        // Suspend
        if (lightdm.can_suspend) {
            elements.btnSuspend.addEventListener('click', function() {
                lightdm.suspend();
            });
        } else {
            elements.btnSuspend.style.display = 'none';
        }
    }

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        // Mode toggle
        elements.toggleMode.addEventListener('click', function() {
            switchMode(currentMode === 'sso' ? 'offline' : 'sso');
        });

        // Offline form submission
        elements.offlineForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleOfflineLogin();
        });

        // Listen for SSO callback messages from iframe
        window.addEventListener('message', handleIframeMessage);

        // Also listen for BroadcastChannel messages
        if (typeof BroadcastChannel !== 'undefined') {
            const channel = new BroadcastChannel('desktop_login');
            channel.addEventListener('message', function(event) {
                handleLoginCallback(event.data);
            });
        }

        // Check for pending login result in localStorage (from callback page).
        // NOTE: For security, the callback page does NOT store access_token in
        // localStorage (XSS risk). The localStorage path only carries metadata
        // (success, user, state) and is used as a signal that SSO completed.
        // The actual token is delivered via postMessage or BroadcastChannel.
        try {
            var storedResult = localStorage.getItem('desktop_login_result');
            if (storedResult) {
                // Remove immediately before processing to minimize exposure
                localStorage.removeItem('desktop_login_result');
                var data = JSON.parse(storedResult);
                if (data && data.type === 'desktop_login_callback') {
                    handleLoginCallback(data);
                }
            }
        } catch (e) {
            // Clear any corrupted data
            localStorage.removeItem('desktop_login_result');
        }

        // LightDM callbacks
        if (typeof lightdm !== 'undefined') {
            lightdm.show_prompt = handleLightDMPrompt;
            lightdm.show_message = handleLightDMMessage;
            lightdm.authentication_complete = handleAuthenticationComplete;
        }
    }

    /**
     * Check if the auth server is reachable
     */
    function checkOnlineStatus() {
        const testUrl = CONFIG.portalUrl + '/desktop/login?check=1';

        fetch(testUrl, {
            method: 'HEAD',
            mode: 'no-cors',
            cache: 'no-cache'
        })
        .then(function() {
            if (!isOnline) {
                debugLog('Auth server is now online');
                isOnline = true;
                updateOnlineStatus();
            }
        })
        .catch(function() {
            if (isOnline) {
                debugLog('Auth server is offline');
                isOnline = false;
                updateOnlineStatus();
            }
        });
    }

    /**
     * Update UI based on online status
     */
    function updateOnlineStatus() {
        const ssoIndicator = elements.ssoMode.querySelector('.mode-indicator');

        if (isOnline) {
            ssoIndicator.classList.remove('offline');
            ssoIndicator.classList.add('online');
            if (currentMode === 'sso') {
                initSSOIframe();
            }
        } else {
            ssoIndicator.classList.remove('online');
            ssoIndicator.classList.add('offline');
            if (currentMode === 'sso') {
                switchMode('offline');
            }
        }
    }

    /**
     * Initialize the SSO iframe
     */
    function initSSOIframe() {
        const iframeUrl = CONFIG.portalUrl + CONFIG.desktopLoginPath +
            '?callback_url=' + encodeURIComponent(window.location.origin + '/callback') +
            '&state=' + generateState();

        debugLog('Loading SSO iframe');
        elements.iframeLoading.classList.remove('hidden');
        elements.ssoIframe.src = iframeUrl;

        elements.ssoIframe.onload = function() {
            elements.iframeLoading.classList.add('hidden');
        };

        elements.ssoIframe.onerror = function() {
            console.error('Failed to load SSO iframe');
            showError('Failed to connect to authentication server');
            switchMode('offline');
        };
    }

    /**
     * Generate a random state parameter for CSRF protection
     */
    function generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, function(b) {
            return b.toString(16).padStart(2, '0');
        }).join('');
    }

    /**
     * Switch between SSO and offline modes
     */
    function switchMode(mode) {
        debugLog('Switching to mode:', mode);
        currentMode = mode;

        if (mode === 'sso') {
            elements.ssoMode.classList.add('active');
            elements.offlineMode.classList.remove('active');
            elements.toggleText.textContent = 'Switch to Offline Mode';
            if (isOnline) {
                initSSOIframe();
            }
        } else {
            elements.offlineMode.classList.add('active');
            elements.ssoMode.classList.remove('active');
            elements.toggleText.textContent = 'Switch to SSO Mode';
            elements.username.focus();
        }

        hideError();
    }

    /**
     * Handle messages from SSO iframe
     */
    function handleIframeMessage(event) {
        // Verify origin - use strict comparison to prevent prefix attacks
        // e.g., https://auth.example.com.evil.com would bypass startsWith()
        var portalOrigin;
        try {
            portalOrigin = new URL(CONFIG.portalUrl).origin;
        } catch (e) {
            console.error('Invalid portal URL:', CONFIG.portalUrl);
            return;
        }
        if (event.origin !== portalOrigin) {
            console.warn('Ignoring message from unknown origin:', event.origin);
            return;
        }

        const data = event.data;
        if (data && data.type === 'desktop_login_callback') {
            handleLoginCallback(data);
        }
    }

    /**
     * Handle login callback (from SSO or iframe)
     */
    function handleLoginCallback(data) {
        debugLog('Received login callback');

        if (data.error) {
            showError(data.error);
            return;
        }

        if (data.access_token && data.user) {
            authToken = data.access_token;
            selectedUser = data.user;

            // Start LightDM authentication with the token as password
            startAuthentication(selectedUser, authToken);
        } else if (data.success && data.user && !data.access_token) {
            // SSO succeeded but token was not included (e.g. localStorage path
            // which excludes tokens for security). Reload SSO iframe to get a
            // fresh token via postMessage.
            initSSOIframe();
        }
    }

    /**
     * Handle offline login form submission
     */
    function handleOfflineLogin() {
        const username = elements.username.value.trim();
        const password = elements.password.value;

        if (!username || !password) {
            showError('Please enter username and password');
            return;
        }

        setLoading(true);

        selectedUser = username;
        // Prefix with OFFLINE: so the PAM module can distinguish offline
        // passwords from OAuth2 tokens when the server is unreachable
        startAuthentication(username, 'OFFLINE:' + password);
    }

    /**
     * Start LightDM authentication
     */
    function startAuthentication(username, password) {
        if (typeof lightdm === 'undefined') {
            console.error('LightDM not available');
            showError('LightDM not available');
            setLoading(false);
            return;
        }

        // Store password in closure-scoped variable (not global for security)
        pendingPassword = password;

        debugLog('Starting LightDM authentication for user:', username);
        lightdm.authenticate(username);
    }

    /**
     * Handle LightDM prompt (password request)
     */
    function handleLightDMPrompt(text, type) {
        debugLog('LightDM prompt type:', type);

        if (type === 1) {  // Password prompt
            if (pendingPassword) {
                lightdm.respond(pendingPassword);
                // Clear password from memory immediately after use
                pendingPassword = null;
            } else {
                console.error('No password available for prompt');
                showError('Authentication error');
                setLoading(false);
            }
        }
    }

    /**
     * Handle LightDM message
     */
    function handleLightDMMessage(text, type) {
        debugLog('LightDM message type:', type);

        if (type === 1) {  // Error message
            showError(text);
        }
    }

    /**
     * Handle authentication completion
     */
    function handleAuthenticationComplete() {
        debugLog('Authentication complete, is_authenticated:', lightdm.is_authenticated);

        setLoading(false);

        if (lightdm.is_authenticated) {
            debugLog('Starting session:', selectedSession);
            lightdm.start_session(selectedSession);
        } else {
            showError('Authentication failed. Please try again.');
            elements.password.value = '';
            elements.password.focus();
        }
    }

    /**
     * Update the clock display
     */
    function updateClock() {
        const now = new Date();

        // Time
        const hours = now.getHours().toString().padStart(2, '0');
        const minutes = now.getMinutes().toString().padStart(2, '0');
        elements.clockTime.textContent = hours + ':' + minutes;

        // Date
        const options = { weekday: 'long', month: 'long', day: 'numeric' };
        elements.clockDate.textContent = now.toLocaleDateString('en-US', options);
    }

    /**
     * Show error message
     */
    function showError(message) {
        elements.errorMessage.textContent = message;
        elements.errorMessage.classList.remove('hidden');
    }

    /**
     * Hide error message
     */
    function hideError() {
        elements.errorMessage.classList.add('hidden');
    }

    /**
     * Set loading state
     */
    function setLoading(loading) {
        if (loading) {
            elements.loginBtn.classList.add('loading');
            elements.loginBtn.disabled = true;
        } else {
            elements.loginBtn.classList.remove('loading');
            elements.loginBtn.disabled = false;
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Mock LightDM for testing outside of greeter
    if (typeof lightdm === 'undefined') {
        console.warn('LightDM not available, using mock');
        window.lightdm = {
            hostname: 'test-machine',
            can_shutdown: true,
            can_restart: true,
            can_suspend: true,
            default_session: 'gnome',
            sessions: [
                { key: 'gnome', name: 'GNOME' },
                { key: 'gnome-xorg', name: 'GNOME on Xorg' },
                { key: 'plasma', name: 'Plasma' }
            ],
            authenticate: function(username) {
                console.log('Mock: authenticate', username);
                setTimeout(function() {
                    lightdm.show_prompt('Password:', 1);
                }, 100);
            },
            respond: function(response) {
                console.log('Mock: respond (password provided)');
                setTimeout(function() {
                    lightdm.is_authenticated = true;
                    lightdm.authentication_complete();
                }, 500);
            },
            start_session: function(session) {
                console.log('Mock: start_session', session);
                alert('Would start session: ' + session);
            },
            shutdown: function() { console.log('Mock: shutdown'); },
            restart: function() { console.log('Mock: restart'); },
            suspend: function() { console.log('Mock: suspend'); },
            show_prompt: function() {},
            show_message: function() {},
            authentication_complete: function() {},
            is_authenticated: false
        };
    }

})();
