(function () {
  'use strict';

  (function () {

    var currentPage = 0;
    var pageSize = 20;
    var totalCerts = 0;
    var revokeModal = null;
    var alertToast = null;

    // Escape HTML to prevent XSS
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    // Get the base URL (script name without trailing slash)
    function getBaseUrl() {
      var path = window.location.pathname;
      // Remove /ssh/admin from the path to get the base
      return path.replace(/\/ssh\/admin\/?$/, '');
    }

    // Format timestamp to readable date
    function formatDate(timestamp) {
      if (!timestamp) return '-';
      var d = new Date(timestamp * 1000);
      return d.toLocaleString();
    }

    // Get status badge HTML
    function getStatusBadge(status) {
      var badgeClass = 'bg-secondary';
      var text = status;
      switch (status) {
        case 'active':
          badgeClass = 'bg-success';
          break;
        case 'expired':
          badgeClass = 'bg-secondary';
          break;
        case 'revoked':
          badgeClass = 'bg-danger';
          break;
      }
      return '<span class="badge ' + badgeClass + '">' + text + '</span>';
    }

    // Show toast notification
    function showToast(message, type) {
      var toastEl = document.getElementById('alertToast');
      var toastIcon = document.getElementById('toastIcon');
      var toastTitle = document.getElementById('toastTitle');
      var toastMessage = document.getElementById('toastMessage');
      toastMessage.textContent = message;
      if (type === 'success') {
        toastIcon.className = 'fa fa-check-circle me-2 text-success';
        toastTitle.textContent = 'Success';
      } else if (type === 'error') {
        toastIcon.className = 'fa fa-exclamation-circle me-2 text-danger';
        toastTitle.textContent = 'Error';
      } else {
        toastIcon.className = 'fa fa-info-circle me-2 text-info';
        toastTitle.textContent = 'Info';
      }
      if (!alertToast) {
        alertToast = new bootstrap.Toast(toastEl);
      }
      alertToast.show();
    }

    // Load certificates from API
    function loadCertificates(page) {
      currentPage = page || 0;
      var offset = currentPage * pageSize;
      var params = new URLSearchParams();
      params.set('limit', pageSize);
      params.set('offset', offset);
      var user = document.getElementById('searchUser').value.trim();
      var serial = document.getElementById('searchSerial').value.trim();
      var keyId = document.getElementById('searchKeyId').value.trim();
      var status = document.getElementById('searchStatus').value;
      if (user) params.set('user', user);
      if (serial) params.set('serial', serial);
      if (keyId) params.set('key_id', keyId);
      if (status) params.set('status', status);
      var tableBody = document.getElementById('certsTable');
      var loadingRow = document.getElementById('loadingRow');
      var noResultsRow = document.getElementById('noResultsRow');
      var searchPromptRow = document.getElementById('searchPromptRow');

      // Show loading
      loadingRow.classList.remove('d-none');
      noResultsRow.classList.add('d-none');
      if (searchPromptRow) searchPromptRow.classList.add('d-none');

      // Remove existing cert rows
      var existingRows = tableBody.querySelectorAll('.cert-row');
      existingRows.forEach(function (row) {
        row.remove();
      });
      var baseUrl = getBaseUrl();
      $.ajax({
        type: 'GET',
        url: baseUrl + '/ssh/certs?' + params.toString(),
        dataType: 'json',
        success: function success(data) {
          loadingRow.classList.add('d-none');
          totalCerts = data.total || 0;
          document.getElementById('resultCount').textContent = totalCerts;
          if (!data.certificates || data.certificates.length === 0) {
            noResultsRow.classList.remove('d-none');
            updatePagination();
            return;
          }
          noResultsRow.classList.add('d-none');
          data.certificates.forEach(function (cert) {
            var row = document.createElement('tr');
            row.className = 'cert-row';
            row.innerHTML = '<td>' + escapeHtml(cert.serial || '-') + '</td>' + '<td>' + escapeHtml(cert.user || '-') + '</td>' + '<td><code>' + escapeHtml(cert.principals || '-') + '</code></td>' + '<td>' + escapeHtml(formatDate(cert.issued_at)) + '</td>' + '<td>' + escapeHtml(formatDate(cert.expires_at)) + '</td>' + '<td>' + getStatusBadge(cert.status) + '</td>' + '<td>' + getActionButtons(cert) + '</td>';
            tableBody.appendChild(row);
          });

          // Bind revoke buttons
          tableBody.querySelectorAll('.btn-revoke').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
              e.preventDefault();
              showRevokeModal(this.dataset.sessionId, this.dataset.serial, this.dataset.user, this.dataset.keyId);
            });
          });
          updatePagination();
        },
        error: function error(xhr, status, _error) {
          loadingRow.classList.add('d-none');
          noResultsRow.classList.remove('d-none');
          noResultsRow.querySelector('td').textContent = 'Error loading certificates: ' + (_error || status);
          showToast('Failed to load certificates', 'error');
        }
      });
    }

    // Get action buttons HTML for a certificate
    function getActionButtons(cert) {
      if (cert.status === 'revoked') {
        return '<span class="text-muted" title="Revoked by ' + escapeHtml(cert.revoked_by || 'unknown') + ' at ' + escapeHtml(formatDate(cert.revoked_at)) + '">' + '<span class="fa fa-ban"></span> Revoked</span>';
      }
      return '<button class="btn btn-sm btn-outline-danger btn-revoke" ' + 'data-session-id="' + escapeHtml(cert.session_id) + '" ' + 'data-serial="' + escapeHtml(cert.serial || '') + '" ' + 'data-user="' + escapeHtml(cert.user || '') + '" ' + 'data-key-id="' + escapeHtml(cert.key_id || '') + '">' + '<span class="fa fa-ban"></span> Revoke</button>';
    }

    // Update pagination
    function updatePagination() {
      var pagination = document.getElementById('pagination');
      pagination.innerHTML = '';
      var totalPages = Math.ceil(totalCerts / pageSize);
      if (totalPages <= 1) return;

      // Previous button
      var prevLi = document.createElement('li');
      prevLi.className = 'page-item' + (currentPage === 0 ? ' disabled' : '');
      prevLi.innerHTML = '<a class="page-link" href="#" data-page="' + (currentPage - 1) + '">&laquo;</a>';
      pagination.appendChild(prevLi);

      // Page numbers
      var startPage = Math.max(0, currentPage - 2);
      var endPage = Math.min(totalPages - 1, currentPage + 2);
      for (var i = startPage; i <= endPage; i++) {
        var li = document.createElement('li');
        li.className = 'page-item' + (i === currentPage ? ' active' : '');
        li.innerHTML = '<a class="page-link" href="#" data-page="' + i + '">' + (i + 1) + '</a>';
        pagination.appendChild(li);
      }

      // Next button
      var nextLi = document.createElement('li');
      nextLi.className = 'page-item' + (currentPage >= totalPages - 1 ? ' disabled' : '');
      nextLi.innerHTML = '<a class="page-link" href="#" data-page="' + (currentPage + 1) + '">&raquo;</a>';
      pagination.appendChild(nextLi);

      // Bind click handlers
      pagination.querySelectorAll('.page-link').forEach(function (link) {
        link.addEventListener('click', function (e) {
          e.preventDefault();
          var page = parseInt(this.dataset.page);
          if (!isNaN(page) && page >= 0 && page < totalPages) {
            loadCertificates(page);
          }
        });
      });
    }

    // Show revoke modal
    function showRevokeModal(sessionId, serial, user, keyId) {
      document.getElementById('revokeSessionId').value = sessionId;
      document.getElementById('revokeSerialInput').value = serial;
      document.getElementById('revokeSerial').textContent = serial;
      document.getElementById('revokeUser').textContent = user;
      document.getElementById('revokeKeyId').textContent = keyId;
      document.getElementById('revokeReason').value = '';
      if (!revokeModal) {
        revokeModal = new bootstrap.Modal(document.getElementById('revokeModal'));
      }
      revokeModal.show();
    }

    // Perform revocation
    function revokeCertificate() {
      var sessionId = document.getElementById('revokeSessionId').value;
      var serial = document.getElementById('revokeSerialInput').value;
      var reason = document.getElementById('revokeReason').value.trim();
      var baseUrl = getBaseUrl();
      $.ajax({
        type: 'POST',
        url: baseUrl + '/ssh/revoke',
        contentType: 'application/json',
        data: JSON.stringify({
          session_id: sessionId,
          serial: serial,
          reason: reason
        }),
        dataType: 'json',
        success: function success(data) {
          revokeModal.hide();
          if (data.result) {
            showToast('Certificate revoked successfully', 'success');
            loadCertificates(currentPage);
          } else {
            showToast(data.error || 'Failed to revoke certificate', 'error');
          }
        },
        error: function error(xhr, status, _error2) {
          revokeModal.hide();
          var msg = _error2 || status;
          try {
            var resp = JSON.parse(xhr.responseText);
            if (resp.error) msg = resp.error;
          } catch (e) {}
          showToast('Failed to revoke certificate: ' + msg, 'error');
        }
      });
    }

    // Initialize on page load
    $(window).on('load', function () {
      // Search form submit
      document.getElementById('searchForm').addEventListener('submit', function (e) {
        e.preventDefault();
        loadCertificates(0);
      });

      // Reset search - clear form and show search prompt
      document.getElementById('resetSearch').addEventListener('click', function () {
        document.getElementById('searchUser').value = '';
        document.getElementById('searchSerial').value = '';
        document.getElementById('searchKeyId').value = '';
        document.getElementById('searchStatus').value = '';
        // Clear results
        var tableBody = document.getElementById('certsTable');
        var existingRows = tableBody.querySelectorAll('.cert-row');
        existingRows.forEach(function (row) {
          row.remove();
        });
        document.getElementById('loadingRow').classList.add('d-none');
        document.getElementById('noResultsRow').classList.add('d-none');
        var searchPromptRow = document.getElementById('searchPromptRow');
        if (searchPromptRow) searchPromptRow.classList.remove('d-none');
        document.getElementById('resultCount').textContent = '0';
        document.getElementById('pagination').innerHTML = '';
        totalCerts = 0;
      });

      // Confirm revoke button
      document.getElementById('confirmRevoke').addEventListener('click', revokeCertificate);

      // No initial load - wait for user to search
      document.getElementById('loadingRow').classList.add('d-none');
    });
  })();

})();
