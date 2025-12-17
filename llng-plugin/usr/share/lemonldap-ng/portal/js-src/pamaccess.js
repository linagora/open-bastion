(function() {
  $(window).on("load", function() {
    var form = document.getElementById('pamTokenForm');
    if (!form) return;

    var resultDiv = document.getElementById('pamTokenResult');
    var errorDiv = document.getElementById('pamTokenError');
    var tokenInput = document.getElementById('pamToken');
    var loginSpan = document.getElementById('pamLogin');
    var expiresSpan = document.getElementById('pamExpiresIn');
    var copyBtn = document.getElementById('copyPamToken');
    var errorMsg = document.getElementById('pamErrorMessage');

    form.addEventListener('submit', function(e) {
      e.preventDefault();
      resultDiv.classList.add('d-none');
      errorDiv.classList.add('d-none');

      var duration = document.getElementById('pamDuration').value;

      $.ajax({
        type: "POST",
        url: scriptname + 'pam',
        data: { duration: duration },
        dataType: "json",
        success: function(data) {
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
        error: function(xhr, status, error) {
          errorMsg.textContent = error || status;
          errorDiv.classList.remove('d-none');
        }
      });
    });

    // Copy button
    if (copyBtn) {
      copyBtn.addEventListener('click', function() {
        tokenInput.select();
        tokenInput.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(tokenInput.value).then(function() {
          copyBtn.innerHTML = '<span class="fa fa-check"></span>';
          setTimeout(function() {
            copyBtn.innerHTML = '<span class="fa fa-copy"></span>';
          }, 2000);
        });
      });
    }
  });
})();
