<TMPL_INCLUDE NAME="header.tpl">

<div id="logincontent" class="container">

  <script type="text/javascript" src="<TMPL_VAR NAME="js">"></script>
  <div class="card border-secondary">
    <div class="card-header text-white bg-secondary">
      <h4 class="card-title" trspan="sshCaTitle">SSH Certificate</h4>
    </div>
    <div class="card-body">
      <p trspan="sshCaInfo">Sign your SSH public key to obtain a short-lived certificate for passwordless authentication.</p>

      <form id="sshCaForm" class="mb-4">
        <div class="form-group mb-3">
          <label for="sshPublicKey" trspan="sshPublicKey">SSH Public Key</label>
          <textarea class="form-control font-monospace" id="sshPublicKey" name="public_key" rows="4"
                    placeholder="ssh-ed25519 AAAA... user@host" required></textarea>
          <small class="form-text text-muted" trspan="sshPublicKeyHelp">Paste the contents of your ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub file</small>
        </div>
        <div class="form-group mb-3">
          <label for="sshKeyLabel" trspan="sshKeyLabel">Key name</label>
          <input type="text" class="form-control" id="sshKeyLabel" name="label"
                 maxlength="128" required
                 placeholder="laptop-pro" />
          <small class="form-text text-muted" trspan="sshKeyLabelHelp">A unique label to identify this machine (must be unique among your active keys).</small>
        </div>
        <div class="form-group row mb-3">
          <label class="col-sm-4 col-form-label" for="sshValidity" trspan="sshCertValidity">Certificate validity</label>
          <div class="col-sm-8">
            <select class="form-control" id="sshValidity" name="validity_days" data-max-validity="<TMPL_VAR NAME="MAX_VALIDITY_DAYS">">
              <option value="1" data-trspan="oneDay">1 day</option>
              <option value="7" data-trspan="oneWeek">1 week</option>
              <option value="30" data-trspan="oneMonth" selected>1 month</option>
              <option value="90" data-trspan="threeMonths">3 months</option>
              <option value="180" data-trspan="sixMonths">6 months</option>
              <option value="365" data-trspan="oneYear">1 year</option>
            </select>
            <small class="form-text text-muted">
              <span trspan="sshCaMaxValidity">Maximum allowed</span>: <span id="maxValidityDisplay"><TMPL_VAR NAME="MAX_VALIDITY_DAYS"></span> <span trspan="days">days</span>
            </small>
          </div>
        </div>
        <div class="form-group row">
          <div class="col-sm-8 offset-sm-4">
            <button type="submit" class="btn btn-primary" id="signSshKey">
              <span class="fa fa-certificate"></span>
              <span trspan="signSshKey">Sign Key</span>
            </button>
          </div>
        </div>
      </form>

      <div id="sshMyCerts" class="d-none mb-4">
        <h5 trspan="sshMyCertsTitle">My Certificates</h5>
        <div class="table-responsive">
          <table class="table table-sm table-striped">
            <thead>
              <tr>
                <th trspan="sshKeyLabel">Name</th>
                <th trspan="sshPrincipals">Principals</th>
                <th trspan="sshIssuedAt">Issued</th>
                <th trspan="sshValidUntil">Valid until</th>
                <th trspan="sshCertStatus">Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="sshMyCertsBody"></tbody>
          </table>
        </div>
      </div>

      <div id="sshCaResult" class="d-none">
        <div class="alert alert-success">
          <h5 trspan="sshCertGenerated">Your SSH Certificate</h5>
          <div class="mb-3">
            <textarea class="form-control font-monospace" id="sshCertificate" rows="3" readonly></textarea>
            <button class="btn btn-outline-secondary btn-sm mt-2" type="button" id="copySshCert">
              <span class="fa fa-copy"></span>
              <span trspan="copyCertificate">Copy certificate</span>
            </button>
          </div>
          <p class="mb-1">
            <strong trspan="sshKeyId">Key ID:</strong>
            <code id="sshKeyId"></code>
          </p>
          <p class="mb-1">
            <strong trspan="sshPrincipals">Principals:</strong>
            <code id="sshPrincipals"></code>
          </p>
          <p class="mb-0">
            <strong trspan="sshValidUntil">Valid until:</strong>
            <span id="sshValidUntil"></span>
          </p>
        </div>
        <div class="alert alert-info">
          <h6 trspan="sshCaInstructions">How to use this certificate</h6>
          <ol class="mb-0">
            <li trspan="sshCaStep1">Save the certificate next to your private key, adding <code>-cert.pub</code> to its name:</li>
            <pre class="bg-light p-2 mt-1 mb-2"><code>~/.ssh/mykey.pub      &rarr;  ~/.ssh/mykey-cert.pub</code></pre>
            <li trspan="sshCaStep2">SSH will automatically use the certificate when connecting:</li>
            <pre class="bg-light p-2 mt-1 mb-2"><code>ssh user@server</code></pre>
            <li trspan="sshCaStep3">Or specify the private key explicitly (SSH finds the matching certificate):</li>
            <pre class="bg-light p-2 mt-1 mb-0"><code>ssh -i ~/.ssh/mykey user@server</code></pre>
          </ol>
        </div>
      </div>

      <div id="sshCaError" class="alert alert-danger d-none">
        <span trspan="sshCaSignError">Failed to sign key</span>: <span id="sshCaErrorMessage"></span>
      </div>
    </div>
  </div>

  <div id="back2portal" class="mt-3">
    <div class="buttons">
      <a href="<TMPL_VAR NAME="PORTAL_URL">" class="btn btn-primary" role="button">
        <span class="fa fa-home"></span>
        <span trspan="goToPortal">Go to portal</span>
      </a>
    </div>
  </div>

</div>

<TMPL_INCLUDE NAME="footer.tpl">
