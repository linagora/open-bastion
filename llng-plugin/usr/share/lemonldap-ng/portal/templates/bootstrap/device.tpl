<TMPL_INCLUDE NAME="header.tpl">

<div id="logincontent" class="container">

  <TMPL_IF NAME="DEVICE_APPROVED">
    <!-- Device authorization approved -->
    <div class="card border-success">
      <div class="card-header text-white bg-success">
        <h3 class="card-title">
          <span class="fa fa-check-circle"></span>
          <span trspan="deviceApproved">Device Approved</span>
        </h3>
      </div>
      <div class="card-body">
        <p trspan="deviceApprovedMsg">The device has been authorized. You can close this window.</p>
        <TMPL_IF NAME="CLIENT_ID">
          <p>
            <strong trspan="clientId">Client ID</strong>: <TMPL_VAR NAME="CLIENT_ID">
          </p>
        </TMPL_IF>
        <TMPL_IF NAME="SCOPE">
          <p>
            <strong trspan="requestedScope">Requested scope</strong>: <TMPL_VAR NAME="SCOPE">
          </p>
        </TMPL_IF>
      </div>
    </div>

  <TMPL_ELSE>
    <TMPL_IF NAME="DEVICE_DENIED">
      <!-- Device authorization denied -->
      <div class="card border-danger">
        <div class="card-header text-white bg-danger">
          <h3 class="card-title">
            <span class="fa fa-times-circle"></span>
            <span trspan="deviceDenied">Device Denied</span>
          </h3>
        </div>
        <div class="card-body">
          <p trspan="deviceDeniedMsg">The device authorization has been denied. You can close this window.</p>
        </div>
      </div>

    <TMPL_ELSE>
      <!-- Device code entry form -->
      <form id="deviceform" action="<TMPL_VAR NAME="PORTAL_URL">device" method="post" class="login" role="form">

        <input type="hidden" name="skin" value="<TMPL_VAR NAME="SKIN">" />

        <div class="card border-info">
          <div class="card-header text-white bg-info">
            <h3 class="card-title">
              <span class="fa fa-desktop"></span>
              <span trspan="deviceAuthorization">Device Authorization</span>
            </h3>
          </div>
          <div class="card-body">

            <p trspan="deviceAuthorizationMsg">Enter the code displayed on your device to authorize it.</p>

            <TMPL_IF NAME="ERROR">
              <div class="alert alert-danger">
                <span class="fa fa-exclamation-triangle"></span>
                <span trspan="<TMPL_VAR NAME="MSG">"><TMPL_VAR NAME="MSG"></span>
              </div>
            </TMPL_IF>

            <div class="form-group">
              <label for="user_code" trspan="userCode">Device Code</label>
              <input type="text"
                     name="user_code"
                     id="user_code"
                     class="form-control form-control-lg text-center text-uppercase"
                     value="<TMPL_VAR NAME="USER_CODE">"
                     placeholder="XXXX-XXXX"
                     pattern="[A-Za-z0-9\-]{6,12}"
                     maxlength="12"
                     autocomplete="off"
                     autofocus
                     required />
              <small class="form-text text-muted" trspan="userCodeHelp">Enter the 8-character code shown on your device</small>
            </div>

            <div class="buttons">
              <button type="submit" name="action" value="approve" class="btn btn-success btn-lg">
                <span class="fa fa-check"></span>
                <span trspan="authorize">Authorize</span>
              </button>
              <button type="submit" name="action" value="deny" class="btn btn-danger">
                <span class="fa fa-times"></span>
                <span trspan="deny">Deny</span>
              </button>
            </div>

          </div>
        </div>

      </form>
    </TMPL_IF>
  </TMPL_IF>

  <div id="back2portal">
    <div class="buttons">
      <a href="<TMPL_VAR NAME="PORTAL_URL">" class="btn btn-primary" role="button">
        <span class="fa fa-home"></span>
        <span trspan="goToPortal">Go to portal</span>
      </a>
    </div>
  </div>

</div>

<TMPL_INCLUDE NAME="footer.tpl">
