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
          <li trspan="sshCaStep1">Save the certificate to a file next to your private key:</li>
          <pre class="bg-light p-2 mt-1 mb-2"><code>~/.ssh/id_ed25519-cert.pub</code></pre>
          <li trspan="sshCaStep2">SSH will automatically use the certificate when connecting:</li>
          <pre class="bg-light p-2 mt-1 mb-2"><code>ssh user@server</code></pre>
          <li trspan="sshCaStep3">Or specify it explicitly:</li>
          <pre class="bg-light p-2 mt-1 mb-0"><code>ssh -i ~/.ssh/id_ed25519 user@server</code></pre>
        </ol>
      </div>
    </div>

    <div id="sshCaError" class="alert alert-danger d-none">
      <span trspan="sshCaSignError">Failed to sign key</span>: <span id="sshCaErrorMessage"></span>
    </div>
  </div>
</div>
