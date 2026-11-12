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

      // navigator.clipboard only exists in a secure context: over plain HTTP,
      // copy the selection instead. When the API exists but rejects the write
      // (Permissions-Policy clipboard-write, denied permission), honour that
      // refusal and leave the field selected for a manual copy.
      // execCommand('copy') also returns true for an empty selection, hence
      // the check that the selection covers the whole value.
      function copyField(field, done) {
        var scrollTop = field.scrollTop;
        field.focus();
        field.select();
        field.setSelectionRange(0, field.value.length);
        field.scrollTop = scrollTop;
        if (!field.value) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(field.value).then(done, function () {});
          return;
        }
        var ok = false;
        try {
          ok = field.selectionStart === 0
            && field.selectionEnd === field.value.length
            && document.execCommand('copy');
        } catch (e) {}
        if (ok) done();
      }

      // Copy button
      if (copyBtn) {
        var copyTimer = null;
        copyBtn.addEventListener('click', function () {
          copyField(tokenInput, function () {
            copyBtn.innerHTML = '<span class="fa fa-check"></span>';
            clearTimeout(copyTimer);
            copyTimer = setTimeout(function () {
              copyBtn.innerHTML = '<span class="fa fa-copy"></span>';
            }, 2000);
          });
        });
      }
    });
  })();

})();
