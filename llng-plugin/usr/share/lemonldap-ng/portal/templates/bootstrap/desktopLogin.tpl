<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Desktop Login</title>
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
    .login-card {
      background: rgba(255, 255, 255, 0.95);
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }
    .logo {
      text-align: center;
      margin-bottom: 30px;
    }
    .logo svg {
      width: 64px;
      height: 64px;
      fill: #2a5298;
    }
    .logo h1 {
      font-size: 1.5em;
      color: #333;
      margin-top: 10px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    .form-group label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
      color: #555;
    }
    .form-group input {
      width: 100%;
      padding: 14px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .form-group input:focus {
      outline: none;
      border-color: #2a5298;
      box-shadow: 0 0 0 3px rgba(42, 82, 152, 0.2);
    }
    .form-group input::placeholder {
      color: #999;
    }
    .btn-login {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #2a5298 0%, #1e3c72 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn-login:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(42, 82, 152, 0.4);
    }
    .btn-login:active {
      transform: translateY(0);
    }
    .btn-login:disabled {
      opacity: 0.7;
      cursor: not-allowed;
      transform: none;
    }
    .error-message {
      background: #fee2e2;
      color: #dc2626;
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 20px;
      display: none;
    }
    .error-message.visible {
      display: block;
    }
    .spinner {
      display: none;
      width: 20px;
      height: 20px;
      border: 2px solid #ffffff;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin-right: 8px;
      vertical-align: middle;
    }
    .loading .spinner {
      display: inline-block;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
      </svg>
      <h1>Desktop Login</h1>
    </div>

    <div id="errorMessage" class="error-message"></div>

    <form id="loginForm" method="POST" action="<TMPL_VAR NAME="PORTAL_URL" ESCAPE="HTML">/desktop/login">
      <input type="hidden" name="callback_url" value="<TMPL_VAR NAME="CALLBACK_URL" ESCAPE="HTML">">
      <input type="hidden" name="state" value="<TMPL_VAR NAME="STATE" ESCAPE="HTML">">
      <input type="hidden" name="csrf_token" value="<TMPL_VAR NAME="CSRF_TOKEN" ESCAPE="HTML">">

      <div class="form-group">
        <label for="user">Username</label>
        <input type="text" id="user" name="user" placeholder="Enter your username" required autofocus>
      </div>

      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter your password" required>
      </div>

      <button type="submit" class="btn-login" id="submitBtn">
        <span class="spinner"></span>
        <span class="btn-text">Sign In</span>
      </button>
    </form>
  </div>

  <script>
    (function() {
      var form = document.getElementById('loginForm');
      var submitBtn = document.getElementById('submitBtn');
      var errorDiv = document.getElementById('errorMessage');

      form.addEventListener('submit', function(e) {
        // Add loading state
        submitBtn.classList.add('loading');
        submitBtn.disabled = true;
        submitBtn.querySelector('.btn-text').textContent = 'Signing in...';
      });

      // Check for error in URL hash
      var hash = window.location.hash.substring(1);
      if (hash) {
        var params = new URLSearchParams(hash);
        var error = params.get('error');
        if (error) {
          errorDiv.textContent = decodeURIComponent(error);
          errorDiv.classList.add('visible');
        }
      }

      // Check for error query parameter
      var urlParams = new URLSearchParams(window.location.search);
      var errorParam = urlParams.get('error');
      if (errorParam) {
        errorDiv.textContent = decodeURIComponent(errorParam);
        errorDiv.classList.add('visible');
      }
    })();
  </script>
</body>
</html>
