<TMPL_INCLUDE NAME="header.tpl">

<div id="sshcaadmin" class="container">
  <h3 class="mb-4">
    <span class="fa fa-certificate"></span>
    <span trspan="sshCaAdminTitle">SSH Certificate Administration</span>
  </h3>

  <!-- Search Form -->
  <div class="card mb-4">
    <div class="card-header">
      <h5 class="card-title mb-0" trspan="sshCaSearchTitle">Search Certificates</h5>
    </div>
    <div class="card-body">
      <form id="searchForm" class="row g-3">
        <div class="col-md-3">
          <label for="searchUser" class="form-label" trspan="user">User</label>
          <input type="text" class="form-control" id="searchUser" name="user" trplaceholder="user">
        </div>
        <div class="col-md-3">
          <label for="searchSerial" class="form-label" trspan="serial">Serial</label>
          <input type="text" class="form-control" id="searchSerial" name="serial" placeholder="12345">
        </div>
        <div class="col-md-3">
          <label for="searchKeyId" class="form-label" trspan="keyId">Key ID</label>
          <input type="text" class="form-control" id="searchKeyId" name="key_id" placeholder="user@llng-...">
        </div>
        <div class="col-md-3">
          <label for="searchStatus" class="form-label" trspan="status">Status</label>
          <select class="form-select" id="searchStatus" name="status">
            <option value="" trspan="allStatuses">All</option>
            <option value="active" trspan="active">Active</option>
            <option value="expired" trspan="expired">Expired</option>
            <option value="revoked" trspan="revoked">Revoked</option>
          </select>
        </div>
        <div class="col-12">
          <button type="submit" class="btn btn-primary">
            <span class="fa fa-search"></span>
            <span trspan="search">Search</span>
          </button>
          <button type="button" class="btn btn-outline-secondary" id="resetSearch">
            <span class="fa fa-times"></span>
            <span trspan="reset">Reset</span>
          </button>
        </div>
      </form>
    </div>
  </div>

  <!-- Results -->
  <div class="card">
    <div class="card-header d-flex justify-content-between align-items-center">
      <h5 class="card-title mb-0" trspan="certificates">Certificates</h5>
      <span id="resultCount" class="badge bg-secondary">0</span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-striped mb-0">
          <thead>
            <tr>
              <th trspan="serial">Serial</th>
              <th trspan="user">User</th>
              <th trspan="principals">Principals</th>
              <th trspan="issuedAt">Issued</th>
              <th trspan="expiresAt">Expires</th>
              <th trspan="status">Status</th>
              <th trspan="actions">Actions</th>
            </tr>
          </thead>
          <tbody id="certsTable">
            <tr id="loadingRow" class="d-none">
              <td colspan="7" class="text-center">
                <span class="spinner-border spinner-border-sm" role="status"></span>
                <span trspan="loading">Loading...</span>
              </td>
            </tr>
            <tr id="noResultsRow" class="d-none">
              <td colspan="7" class="text-center text-muted" trspan="noResults">No certificates found</td>
            </tr>
            <tr id="searchPromptRow">
              <td colspan="7" class="text-center text-muted" trspan="sshCaSearchPrompt">Enter search criteria and click Search</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="card-footer">
      <nav>
        <ul class="pagination justify-content-center mb-0" id="pagination">
        </ul>
      </nav>
    </div>
  </div>

  <!-- Back link -->
  <div class="buttons mt-4">
    <a href="<TMPL_VAR NAME="PORTAL_URL">" class="btn btn-primary" role="button">
      <span class="fa fa-home"></span>
      <span trspan="goToPortal">Go to portal</span>
    </a>
  </div>
</div>

<!-- Revoke Modal -->
<div class="modal fade" id="revokeModal" tabindex="-1" aria-labelledby="revokeModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="revokeModalLabel" trspan="revokeCertificate">Revoke Certificate</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p trspan="revokeConfirm">Are you sure you want to revoke this certificate?</p>
        <dl>
          <dt trspan="serial">Serial</dt>
          <dd id="revokeSerial"></dd>
          <dt trspan="user">User</dt>
          <dd id="revokeUser"></dd>
          <dt trspan="keyId">Key ID</dt>
          <dd id="revokeKeyId" class="text-break"></dd>
        </dl>
        <div class="mb-3">
          <label for="revokeReason" class="form-label" trspan="revokeReason">Reason (optional)</label>
          <textarea class="form-control" id="revokeReason" rows="2" trplaceholder="revokeReason"></textarea>
        </div>
        <input type="hidden" id="revokeSessionId">
        <input type="hidden" id="revokeSerialInput">
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal" trspan="cancel">Cancel</button>
        <button type="button" class="btn btn-danger" id="confirmRevoke">
          <span class="fa fa-ban"></span>
          <span trspan="revoke">Revoke</span>
        </button>
      </div>
    </div>
  </div>
</div>

<!-- Alert Toast -->
<div class="toast-container position-fixed bottom-0 end-0 p-3">
  <div id="alertToast" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
    <div class="toast-header">
      <span id="toastIcon" class="fa fa-info-circle me-2"></span>
      <strong class="me-auto" id="toastTitle">Notification</strong>
      <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
    <div class="toast-body" id="toastMessage"></div>
  </div>
</div>

<script type="text/javascript" src="<TMPL_VAR NAME="STATIC_PREFIX">common/js/sshcaadmin.js"></script>

<TMPL_INCLUDE NAME="footer.tpl">
