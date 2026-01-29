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
        lockoutDisplayInterval: 1000,           // Update lockout countdown every second
        debug: false                            // Enable debug logging (set via greeter config)
    };

    // Offline error codes (must match PAM module)
    // Offline error codes (must match include/offline_cache.h)
    const OFFLINE_ERRORS = {
        OK: 0,
        NOMEM: -1,       // OFFLINE_CACHE_ERR_NOMEM
        IO: -2,          // OFFLINE_CACHE_ERR_IO
        CRYPTO: -3,      // OFFLINE_CACHE_ERR_CRYPTO
        NOT_FOUND: -4,   // OFFLINE_CACHE_ERR_NOTFOUND
        EXPIRED: -5,     // OFFLINE_CACHE_ERR_EXPIRED
        LOCKED: -6,      // OFFLINE_CACHE_ERR_LOCKED
        INVALID: -7,     // OFFLINE_CACHE_ERR_INVALID
        PASSWORD: -8     // OFFLINE_CACHE_ERR_PASSWORD
    };

    // Error messages for offline authentication failures
    const OFFLINE_ERROR_MESSAGES = {
        [OFFLINE_ERRORS.NOMEM]: 'System resources are low. Please try again or contact your administrator.',
        [OFFLINE_ERRORS.IO]: 'Error reading cached credentials. Please contact administrator.',
        [OFFLINE_ERRORS.CRYPTO]: 'Credential verification failed. Please try again.',
        [OFFLINE_ERRORS.NOT_FOUND]: 'No cached credentials found. Please connect to the network and login online first.',
        [OFFLINE_ERRORS.EXPIRED]: 'Cached credentials have expired. Please connect to the network to refresh.',
        [OFFLINE_ERRORS.LOCKED]: 'Account temporarily locked due to too many failed attempts.',
        [OFFLINE_ERRORS.INVALID]: 'Cached credential data is invalid. Please connect to the network and login again.',
        [OFFLINE_ERRORS.PASSWORD]: 'Invalid password. Please try again.'
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
    let offlineCheckFailures = 0;
    let lastOfflineError = null;
    let lockoutEndTime = null;
    let lockoutTimer = null;
    let onlineCheckTimer = null;

    // DOM Elements (initialized in init())
    let elements = {};

    /**
     * Initialize the greeter
     */
    function init() {
        debugLog('Initializing Open Bastion Greeter');

        // Cache DOM elements
        elements = {
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
            btnSuspend: document.getElementById('btn-suspend'),
            // New offline UI elements
            offlineBanner: document.getElementById('offline-banner'),
            offlineStatus: document.getElementById('offline-status'),
            offlineRetryBtn: document.getElementById('offline-retry-btn'),
            lockoutMessage: document.getElementById('lockout-message'),
            lockoutCountdown: document.getElementById('lockout-countdown')
        };

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

        // Setup event listeners
        setupEventListeners();

        // Initialize mode based on online status
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

        // Offline retry button
        if (elements.offlineRetryBtn) {
            elements.offlineRetryBtn.addEventListener('click', function() {
                elements.offlineRetryBtn.disabled = true;
                checkOnlineStatus(true);
                setTimeout(function() { elements.offlineRetryBtn.disabled = false; }, 3000);
            });
        }

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
     * @param {boolean} manual - Whether this is a manual retry
     */
    function checkOnlineStatus(manual) {
        const testUrl = CONFIG.portalUrl + '/desktop/login?check=1';

        // Show checking status if manual retry
        if (manual && elements.offlineStatus) {
            elements.offlineStatus.textContent = 'Checking connection...';
            elements.offlineStatus.className = 'offline-status checking';
        }

        // Create abort controller for timeout (guard for older webkit2gtk)
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timeoutId = setTimeout(function() {
            if (controller) controller.abort();
        }, CONFIG.onlineCheckTimeout);

        const fetchOpts = { method: 'HEAD', mode: 'no-cors', cache: 'no-cache' };
        if (controller) fetchOpts.signal = controller.signal;

        fetch(testUrl, fetchOpts)
        .then(function() {
            clearTimeout(timeoutId);
            offlineCheckFailures = 0;

            if (!isOnline) {
                debugLog('Auth server is now online');
                isOnline = true;
                updateOnlineStatus();

                // If we were in offline mode due to connectivity, switch to SSO
                if (currentMode === 'offline') {
                    switchMode('sso');
                }
            }

            // Schedule next check
            scheduleOnlineCheck(CONFIG.checkOnlineInterval);
        })
        .catch(function(err) {
            clearTimeout(timeoutId);
            offlineCheckFailures++;

            debugLog('Auth server check failed:', err.message, 'failures:', offlineCheckFailures);

            if (offlineCheckFailures >= CONFIG.maxOfflineCheckRetries && isOnline) {
                debugLog('Auth server is offline after', offlineCheckFailures, 'failures');
                isOnline = false;
                updateOnlineStatus();

                // Auto-switch to offline mode
                if (currentMode === 'sso') {
                    switchMode('offline');
                }
            }

            // Schedule next check (more frequent when offline)
            const interval = isOnline ? CONFIG.checkOnlineInterval : CONFIG.offlineRetryInterval;
            scheduleOnlineCheck(interval);
        });
    }

    /**
     * Schedule the next online status check
     */
    function scheduleOnlineCheck(interval) {
        if (onlineCheckTimer) {
            clearTimeout(onlineCheckTimer);
        }
        onlineCheckTimer = setTimeout(function() {
            checkOnlineStatus(false);
        }, interval);
    }

    /**
     * Update UI based on online status
     */
    function updateOnlineStatus() {
        const ssoIndicator = elements.ssoMode.querySelector('.mode-indicator');

        if (isOnline) {
            ssoIndicator.classList.remove('offline');
            ssoIndicator.classList.add('online');

            // Hide offline banner
            if (elements.offlineBanner) {
                elements.offlineBanner.classList.add('hidden');
            }

            // Update status text
            if (elements.offlineStatus) {
                elements.offlineStatus.textContent = 'Connected';
                elements.offlineStatus.className = 'offline-status online';
            }

            if (currentMode === 'sso') {
                initSSOIframe();
            }
        } else {
            ssoIndicator.classList.remove('online');
            ssoIndicator.classList.add('offline');

            // Show offline banner
            if (elements.offlineBanner) {
                elements.offlineBanner.classList.remove('hidden');
            }

            // Update status text
            if (elements.offlineStatus) {
                elements.offlineStatus.textContent = 'Server unavailable - using cached credentials';
                elements.offlineStatus.className = 'offline-status offline';
            }

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
            offlineCheckFailures = CONFIG.maxOfflineCheckRetries;
            isOnline = false;
            updateOnlineStatus();
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

            // Stop lockout display timer but preserve lockoutEndTime —
            // if user switches back to offline, the lockout is still active.
            stopLockoutDisplay();

            if (isOnline) {
                initSSOIframe();
            } else {
                // Can't use SSO when offline
                showError('Cannot use SSO mode - server is unavailable');
                switchMode('offline');
                return;
            }
        } else {
            elements.offlineMode.classList.add('active');
            elements.ssoMode.classList.remove('active');
            elements.toggleText.textContent = 'Switch to SSO Mode';

            // Show offline info message
            if (!isOnline) {
                showOfflineInfo();
            }

            elements.username.focus();
        }

        hideError();
    }

    /**
     * Show offline mode information
     */
    function showOfflineInfo() {
        if (elements.offlineBanner) {
            elements.offlineBanner.classList.remove('hidden');
        }
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

        // UX-only lockout guard — the PAM module is the authoritative enforcer
        // (via OFFLINE_CACHE_ERR_LOCKED). This just avoids unnecessary round-trips.
        if (lockoutEndTime && Date.now() < lockoutEndTime) {
            showLockoutError();
            return;
        }

        setLoading(true);
        hideError();

        selectedUser = username;
        // Prefix with OFFLINE: so the PAM module can distinguish offline
        // passwords from OAuth2 tokens when the server is unreachable.
        // This constant must match OFFLINE_PASSWORD_PREFIX in include/offline_cache.h
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

        // Parse offline error codes from PAM messages
        const errorMatch = text.match(/OFFLINE_ERROR:(-?\d+)(?::(\d+))?/);
        if (errorMatch) {
            const errorCode = parseInt(errorMatch[1], 10);
            const lockoutTime = errorMatch[2] ? parseInt(errorMatch[2], 10) : null;

            handleOfflineError(errorCode, lockoutTime);
            return;
        }

        if (type === 1) {  // Error message
            showError(text);
        }
    }

    /**
     * Handle offline authentication errors
     */
    function handleOfflineError(errorCode, lockoutTime) {
        lastOfflineError = errorCode;

        if (errorCode === OFFLINE_ERRORS.LOCKED && lockoutTime) {
            // Set lockout end time
            lockoutEndTime = Date.now() + (lockoutTime * 1000);
            showLockoutError();
            startLockoutTimer();
        } else {
            // Show appropriate error message
            const message = OFFLINE_ERROR_MESSAGES[errorCode] || 'Authentication failed';
            showError(message);
        }
    }

    /**
     * Show lockout error with countdown
     */
    function showLockoutError() {
        if (!lockoutEndTime) return;

        const remaining = Math.ceil((lockoutEndTime - Date.now()) / 1000);
        if (remaining <= 0) {
            clearLockoutTimer();
            hideError();
            return;
        }

        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        const timeStr = minutes > 0
            ? minutes + ' minute' + (minutes !== 1 ? 's' : '') + ' ' + seconds + ' second' + (seconds !== 1 ? 's' : '')
            : seconds + ' second' + (seconds !== 1 ? 's' : '');

        showError('Account locked. Try again in ' + timeStr);

        // Disable inputs during lockout
        if (elements.username) elements.username.disabled = true;
        if (elements.password) elements.password.disabled = true;

        // Update lockout countdown element if present
        if (elements.lockoutCountdown) {
            elements.lockoutCountdown.textContent = timeStr;
        }
        if (elements.lockoutMessage) {
            elements.lockoutMessage.classList.remove('hidden');
        }
    }

    /**
     * Start lockout countdown timer
     */
    function startLockoutTimer() {
        clearLockoutTimer();
        lockoutTimer = setInterval(function() {
            if (!lockoutEndTime || Date.now() >= lockoutEndTime) {
                clearLockoutTimer();
                hideError();
                if (elements.lockoutMessage) {
                    elements.lockoutMessage.classList.add('hidden');
                }
            } else {
                showLockoutError();
            }
        }, CONFIG.lockoutDisplayInterval);
    }

    /**
     * Stop the lockout display interval (without clearing lockoutEndTime)
     */
    function stopLockoutDisplay() {
        if (lockoutTimer) {
            clearInterval(lockoutTimer);
            lockoutTimer = null;
        }
    }

    /**
     * Clear lockout state entirely (timer + end time)
     * Only call on actual expiry or successful authentication.
     */
    function clearLockoutTimer() {
        stopLockoutDisplay();
        lockoutEndTime = null;
        // Re-enable inputs after lockout expires
        if (elements.username) elements.username.disabled = false;
        if (elements.password) elements.password.disabled = false;
    }

    /**
     * Handle authentication completion
     */
    function handleAuthenticationComplete() {
        debugLog('Authentication complete, is_authenticated:', lightdm.is_authenticated);

        setLoading(false);

        if (lightdm.is_authenticated) {
            // Clear any lockout state on success
            clearLockoutTimer();

            debugLog('Starting session:', selectedSession);
            lightdm.start_session(selectedSession);
        } else {
            // Check if we have a specific offline error
            if (lastOfflineError !== null) {
                // Error already shown by handleOfflineError
                lastOfflineError = null;
            } else {
                showError('Authentication failed. Please try again.');
            }
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
        elements.errorMessage.classList.add('show');
    }

    /**
     * Hide error message
     */
    function hideError() {
        elements.errorMessage.classList.add('hidden');
        elements.errorMessage.classList.remove('show');
    }

    /**
     * Set loading state
     */
    function setLoading(loading) {
        if (loading) {
            elements.loginBtn.classList.add('loading');
            elements.loginBtn.disabled = true;
            elements.username.disabled = true;
            elements.password.disabled = true;
        } else {
            elements.loginBtn.classList.remove('loading');
            elements.loginBtn.disabled = false;
            elements.username.disabled = false;
            elements.password.disabled = false;
        }
    }

    // Cleanup timers on page unload to prevent leaks
    window.addEventListener('beforeunload', function() {
        clearLockoutTimer();
        if (onlineCheckTimer) {
            clearTimeout(onlineCheckTimer);
            onlineCheckTimer = null;
        }
    });

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
                    // Simulate offline error for testing
                    if (response === 'locked') {
                        lightdm.show_message('OFFLINE_ERROR:-6:300', 1);
                        lightdm.is_authenticated = false;
                    } else if (response === 'expired') {
                        lightdm.show_message('OFFLINE_ERROR:-5', 1);
                        lightdm.is_authenticated = false;
                    } else if (response === 'notfound') {
                        lightdm.show_message('OFFLINE_ERROR:-4', 1);
                        lightdm.is_authenticated = false;
                    } else {
                        lightdm.is_authenticated = true;
                    }
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
