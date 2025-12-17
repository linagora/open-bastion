(function() {
  $(window).on("load", function() {
    var form = document.getElementById('sshCaForm');
    if (!form) return;

    var resultDiv = document.getElementById('sshCaResult');
    var errorDiv = document.getElementById('sshCaError');
    var certTextarea = document.getElementById('sshCertificate');
    var keyIdSpan = document.getElementById('sshKeyId');
    var principalsSpan = document.getElementById('sshPrincipals');
    var validUntilSpan = document.getElementById('sshValidUntil');
    var copyBtn = document.getElementById('copySshCert');
    var errorMsg = document.getElementById('sshCaErrorMessage');

    form.addEventListener('submit', function(e) {
      e.preventDefault();
      resultDiv.classList.add('d-none');
      errorDiv.classList.add('d-none');

      var publicKey = document.getElementById('sshPublicKey').value.trim();
      var validity = document.getElementById('sshValidity').value;

      if (!publicKey) {
        errorMsg.textContent = 'Please paste your SSH public key';
        errorDiv.classList.remove('d-none');
        return;
      }

      $.ajax({
        type: "POST",
        url: scriptname + 'ssh/sign',
        contentType: "application/json",
        data: JSON.stringify({
          public_key: publicKey,
          validity_minutes: parseInt(validity)
        }),
        dataType: "json",
        success: function(data) {
          if (data.error) {
            errorMsg.textContent = data.error;
            errorDiv.classList.remove('d-none');
          } else {
            certTextarea.value = data.certificate;
            keyIdSpan.textContent = data.key_id;
            principalsSpan.textContent = data.principals.join(', ');
            validUntilSpan.textContent = data.valid_until;
            resultDiv.classList.remove('d-none');
          }
        },
        error: function(xhr, status, error) {
          var msg = error || status;
          try {
            var resp = JSON.parse(xhr.responseText);
            if (resp.error) msg = resp.error;
          } catch(e) {}
          errorMsg.textContent = msg;
          errorDiv.classList.remove('d-none');
        }
      });
    });

    // Copy button
    if (copyBtn) {
      copyBtn.addEventListener('click', function() {
        certTextarea.select();
        certTextarea.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(certTextarea.value).then(function() {
          var originalHtml = copyBtn.innerHTML;
          copyBtn.innerHTML = '<span class="fa fa-check"></span> Copied!';
          setTimeout(function() {
            copyBtn.innerHTML = originalHtml;
          }, 2000);
        });
      });
    }
  });
})();
