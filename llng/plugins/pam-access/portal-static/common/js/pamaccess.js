(function () {
  'use strict';

  (function () {
    $(window).on("load", function () {
      var form = document.getElementById('pamTokenForm');
      if (!form) return;
      var resultDiv = document.getElementById('pamTokenResult');
      var errorDiv = document.getElementById('pamTokenError');
      var tokenInput = document.getElementById('pamToken');
      var loginSpan = document.getElementById('pamLogin');
      var expiresSpan = document.getElementById('pamExpiresIn');
      var copyBtn = document.getElementById('copyPamToken');
      var errorMsg = document.getElementById('pamErrorMessage');
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        resultDiv.classList.add('d-none');
        errorDiv.classList.add('d-none');
        var duration = document.getElementById('pamDuration').value;
        $.ajax({
          type: "POST",
          url: scriptname + 'pam',
          data: {
            duration: duration
          },
          dataType: "json",
          success: function success(data) {
            if (data.error) {
              errorMsg.textContent = data.error;
              errorDiv.classList.remove('d-none');
            } else {
              tokenInput.value = data.token;
              loginSpan.textContent = data.login;
              var minutes = Math.floor(data.expires_in / 60);
              var seconds = data.expires_in % 60;
              expiresSpan.textContent = minutes + ' min ' + (seconds > 0 ? seconds + ' sec' : '');
              resultDiv.classList.remove('d-none');
            }
          },
          error: function error(xhr, status, _error) {
            errorMsg.textContent = _error || status;
            errorDiv.classList.remove('d-none');
          }
        });
      });

      // Copy the selected field. navigator.clipboard only exists in a secure
      // context (HTTPS or localhost), so a portal served over plain HTTP falls
      // back to execCommand('copy') on the selection (#451). If both fail, the
      // text stays selected for a manual copy.
      function copyField(field, done) {
        field.focus();
        field.select();
        field.setSelectionRange(0, field.value.length);
        var legacy = function () {
          var ok = false;
          try {
            ok = document.execCommand('copy');
          } catch (e) {}
          if (ok) done();
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(field.value).then(done, legacy);
        } else {
          legacy();
        }
      }

      // Copy button
      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          copyField(tokenInput, function () {
            copyBtn.innerHTML = '<span class="fa fa-check"></span>';
            setTimeout(function () {
              copyBtn.innerHTML = '<span class="fa fa-copy"></span>';
            }, 2000);
          });
        });
      }
    });
  })();

})();
