<script type="text/javascript" src="<TMPL_VAR NAME="js">"></script>
<div class="card border-secondary">
  <div class="card-header text-white bg-secondary">
    <h4 class="card-title" trspan="pamAccessTitle">PAM Access Token</h4>
  </div>
  <div class="card-body">
    <p trspan="pamAccessInfo">Generate a temporary token to use as your password for SSH or other PAM-enabled services.</p>

    <form id="pamTokenForm" class="mb-4">
      <div class="form-group row mb-3">
        <label class="col-sm-4 col-form-label" for="pamDuration" trspan="pamTokenDuration">Token validity</label>
        <div class="col-sm-8">
          <select class="form-control" id="pamDuration" name="duration">
            <option value="60">1 minute</option>
            <option value="300">5 minutes</option>
            <option value="600" selected>10 minutes</option>
            <option value="1800">30 minutes</option>
            <option value="3600">1 hour</option>
          </select>
        </div>
      </div>
      <div class="form-group row">
        <div class="col-sm-8 offset-sm-4">
          <button type="submit" class="btn btn-primary" id="generatePamToken">
            <span class="fa fa-key"></span>
            <span trspan="generatePamToken">Generate Token</span>
          </button>
        </div>
      </div>
    </form>

    <div id="pamTokenResult" class="d-none">
      <div class="alert alert-success">
        <h5 trspan="pamTokenGenerated">Your temporary token</h5>
        <div class="input-group mb-3">
          <input type="text" class="form-control font-monospace" id="pamToken" readonly>
          <button class="btn btn-outline-secondary" type="button" id="copyPamToken" title="Copy">
            <span class="fa fa-copy"></span>
          </button>
        </div>
        <p class="mb-1">
          <strong trspan="pamLogin">Login:</strong>
          <code id="pamLogin"></code>
        </p>
        <p class="mb-0">
          <strong trspan="pamExpiresIn">Expires in:</strong>
          <span id="pamExpiresIn"></span>
        </p>
      </div>
      <div class="alert alert-info">
        <h6 trspan="pamInstructions">Instructions</h6>
        <p class="mb-0" trspan="pamInstructionsText">Use this token as your password when connecting via SSH or other PAM-enabled services.</p>
      </div>
    </div>

    <div id="pamTokenError" class="alert alert-danger d-none">
      <span trspan="pamTokenError">Failed to generate token</span>: <span id="pamErrorMessage"></span>
    </div>
  </div>
</div>
