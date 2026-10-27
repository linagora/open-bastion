(function () {
  'use strict';

  (function () {
    $(window).on("load", function () {
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
      var validitySelect = document.getElementById('sshValidity');
      var myCertsDiv = document.getElementById('sshMyCerts');
      var myCertsBody = document.getElementById('sshMyCertsBody');
      var labelInput = document.getElementById('sshKeyLabel');
      var publicKeyArea = document.getElementById('sshPublicKey');

      // Auto-fill the label field from the SSH key comment (3rd token)
      // unless the user has already typed something.
      var labelTouched = false;
      if (labelInput) {
        labelInput.addEventListener('input', function () { labelTouched = true; });
      }
      if (publicKeyArea && labelInput) {
        publicKeyArea.addEventListener('input', function () {
          if (labelTouched && labelInput.value) return;
          var parts = publicKeyArea.value.trim().split(/\s+/);
          if (parts.length >= 3) {
            labelInput.value = parts.slice(2).join(' ').slice(0, 128);
          }
        });
      }

      function revokeCert(serial, btn) {
        if (!serial) return;
        var confirmMsg = window.translate('sshConfirmRevoke');
        if (!window.confirm(confirmMsg)) return;
        if (btn) btn.disabled = true;
        $.ajax({
          type: "POST",
          url: scriptname + 'ssh/myrevoke',
          contentType: "application/json",
          data: JSON.stringify({ serial: String(serial) }),
          dataType: "json",
          success: function () { loadMyCerts(); },
          error: function (xhr) {
            var msg = window.translate('sshRevokeError');
            try {
              var resp = JSON.parse(xhr.responseText);
              if (resp.error) msg = resp.error;
            } catch (e) {}
            errorMsg.textContent = msg;
            errorDiv.classList.remove('d-none');
            if (btn) btn.disabled = false;
          }
        });
      }

      function loadMyCerts() {
        $.getJSON(scriptname + 'ssh/mycerts', function (data) {
          if (data.certificates && data.certificates.length > 0) {
            myCertsBody.innerHTML = '';
            data.certificates.forEach(function (cert) {
              var tr = document.createElement('tr');
              var issuedDate = cert.issued_at ? new Date(cert.issued_at * 1000).toLocaleDateString() : '-';
              var expiresDate = cert.expires_at ? new Date(cert.expires_at * 1000).toLocaleDateString() : '-';
              var statusClass = cert.status === 'active' ? 'text-success' : (cert.status === 'expired' ? 'text-muted' : 'text-danger');
              var statusText = window.translate('sshCertStatus_' + cert.status);
              var labelText = cert.label || cert.key_id || '-';
              var labelCell = $('<span>').text(labelText).html();
              if (cert.fingerprint) {
                labelCell = '<div>' + labelCell + '</div><small class="text-muted font-monospace">'
                  + $('<span>').text(cert.fingerprint).html() + '</small>';
              }
              var actionCell = '';
              if (cert.status === 'active' && cert.serial) {
                actionCell = '<button type="button" class="btn btn-sm btn-outline-danger sshRevokeBtn" data-serial="'
                  + $('<span>').text(cert.serial).html() + '">'
                  + '<span class="fa fa-ban"></span> '
                  + '<span trspan="sshRevoke">Revoke</span></button>';
              }
              tr.innerHTML = '<td>' + labelCell + '</td>'
                + '<td>' + $('<span>').text(cert.principals || '-').html() + '</td>'
                + '<td>' + issuedDate + '</td>'
                + '<td>' + expiresDate + '</td>'
                + '<td class="' + statusClass + '">' + statusText + '</td>'
                + '<td class="text-end">' + actionCell + '</td>';
              myCertsBody.appendChild(tr);
            });
            myCertsBody.querySelectorAll('.sshRevokeBtn').forEach(function (btn) {
              btn.addEventListener('click', function () {
                revokeCert(btn.dataset.serial, btn);
              });
            });
            if (window.translatePage && window.currentLanguage) {
              window.translatePage(window.currentLanguage);
            }
            myCertsDiv.classList.remove('d-none');
          } else {
            myCertsDiv.classList.add('d-none');
          }
        });
      }
      loadMyCerts();

      // Filter validity options based on max validity
      if (validitySelect) {
        var maxValidity = parseInt(validitySelect.dataset.maxValidity) || 365;
        var options = validitySelect.querySelectorAll('option');
        var lastValidOption = null;
        options.forEach(function (option) {
          var value = parseInt(option.value);
          if (value > maxValidity) {
            option.remove();
          } else {
            lastValidOption = option;
          }
        });

        // Select the highest valid option if the default was removed
        var selectedOption = validitySelect.querySelector('option[selected]');
        if (!selectedOption && lastValidOption) {
          lastValidOption.selected = true;
        }
      }
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        resultDiv.classList.add('d-none');
        errorDiv.classList.add('d-none');
        var publicKey = publicKeyArea.value.trim();
        var validityDays = parseInt(validitySelect.value);
        var label = labelInput ? labelInput.value.trim() : '';
        if (!publicKey) {
          errorMsg.textContent = window.translate('sshPublicKeyMissing');
          errorDiv.classList.remove('d-none');
          return;
        }
        if (!label) {
          errorMsg.textContent = window.translate('sshKeyLabelMissing');
          errorDiv.classList.remove('d-none');
          return;
        }
        $.ajax({
          type: "POST",
          url: scriptname + 'ssh/sign',
          contentType: "application/json",
          data: JSON.stringify({
            public_key: publicKey,
            validity_days: validityDays,
            label: label
          }),
          dataType: "json",
          success: function success(data) {
            if (data.error) {
              errorMsg.textContent = data.error;
              errorDiv.classList.remove('d-none');
            } else {
              certTextarea.value = data.certificate;
              keyIdSpan.textContent = data.key_id;
              principalsSpan.textContent = data.principals.join(', ');
              validUntilSpan.textContent = data.valid_until;
              resultDiv.classList.remove('d-none');
              loadMyCerts();
            }
          },
          error: function error(xhr, status, _error) {
            var msg = _error || status;
            try {
              var resp = JSON.parse(xhr.responseText);
              if (resp.error) msg = resp.error;
            } catch (e) {}
            errorMsg.textContent = msg;
            errorDiv.classList.remove('d-none');
          }
        });
      });

      // Copy button
      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          certTextarea.select();
          certTextarea.setSelectionRange(0, 99999);
          navigator.clipboard.writeText(certTextarea.value).then(function () {
            var originalHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = '<span class="fa fa-check"></span> Copied!';
            setTimeout(function () {
              copyBtn.innerHTML = originalHtml;
            }, 2000);
          });
        });
      }
    });
  })();

})();
