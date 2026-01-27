<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Complete</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .callback-card {
      background: rgba(255, 255, 255, 0.95);
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      text-align: center;
    }
    .success-icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 20px;
      background: #10b981;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .success-icon svg {
      width: 40px;
      height: 40px;
      fill: white;
    }
    .error-icon {
      background: #ef4444;
    }
    h1 {
      font-size: 1.5em;
      color: #333;
      margin-bottom: 10px;
    }
    p {
      color: #666;
      margin-bottom: 20px;
    }
    .spinner {
      width: 40px;
      height: 40px;
      border: 4px solid #e0e0e0;
      border-top-color: #2a5298;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 20px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .hidden {
      display: none;
    }
  </style>
</head>
<body>
  <div class="callback-card">
    <TMPL_IF NAME="ERROR">
      <!-- Error state -->
      <div class="success-icon error-icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
        </svg>
      </div>
      <h1>Authentication Failed</h1>
      <p><TMPL_VAR NAME="ERROR"></p>
    <TMPL_ELSE>
      <!-- Success state -->
      <div id="loadingState">
        <div class="spinner"></div>
        <h1>Authentication Successful</h1>
        <p>Completing login for <strong><TMPL_VAR NAME="USER"></strong>...</p>
      </div>
      <div id="successState" class="hidden">
        <div class="success-icon">
          <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
          </svg>
        </div>
        <h1>Login Complete</h1>
        <p>You can now close this window.</p>
      </div>
    </TMPL_IF>
  </div>

  <script>
    (function() {
      // Message data is passed as pre-encoded JSON from server to prevent XSS
      // The server encodes sensitive values safely before embedding
      var messageData = <TMPL_VAR NAME="MESSAGE_JSON">;

      // Prepare the message to send to parent window
      var message = {
        type: 'desktop_login_callback',
        success: !messageData.error,
        error: messageData.error || null,
        access_token: messageData.access_token || null,
        expires_in: messageData.expires_in || null,
        user: messageData.user || null,
        state: messageData.state || null
      };

      // Get the allowed parent origin from server
      var allowedOrigin = messageData.allowed_origin || null;

      // Function to show success state
      function showSuccess() {
        var loadingState = document.getElementById('loadingState');
        var successState = document.getElementById('successState');
        if (loadingState && successState) {
          loadingState.classList.add('hidden');
          successState.classList.remove('hidden');
        }
      }

      // Try to send message to parent window (for iframe usage)
      // SECURITY: Only send to specified origin, never use '*'
      if (window.parent && window.parent !== window && allowedOrigin) {
        try {
          window.parent.postMessage(message, allowedOrigin);
          // NOTE: Never log tokens or sensitive data
        } catch (e) {
          console.warn('Failed to post message to parent');
        }
      }

      // Also try to communicate with LightDM webkit greeter
      if (typeof window.lightdm !== 'undefined') {
        // LightDM greeter context
        try {
          if (messageData.access_token && messageData.user) {
            // Store credentials for PAM authentication
            window.lightdm_token = messageData.access_token;
            window.lightdm_user = messageData.user;
          }
        } catch (e) {
          console.warn('Failed to store credentials for LightDM');
        }
      }

      // Broadcast via BroadcastChannel API if available (same-origin communication)
      // Note: BroadcastChannel is same-origin only, so it's safe
      if (typeof BroadcastChannel !== 'undefined') {
        try {
          var channel = new BroadcastChannel('desktop_login');
          channel.postMessage(message);
          channel.close();
        } catch (e) {
          console.warn('BroadcastChannel failed');
        }
      }

      // Store result in localStorage for polling-based communication
      try {
        if (messageData.access_token) {
          localStorage.setItem('desktop_login_result', JSON.stringify(message));
        }
      } catch (e) {
        console.warn('localStorage failed');
      }

      // If we have a redirect URL and not in iframe, redirect
      if (messageData.redirect_url && window.parent === window) {
        setTimeout(function() {
          window.location.href = messageData.redirect_url;
        }, 1000);
      } else if (messageData.access_token) {
        // Show success state after a short delay
        setTimeout(showSuccess, 500);
      }
    })();
  </script>
</body>
</html>
