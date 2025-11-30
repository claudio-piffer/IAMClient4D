object UniServerModule: TUniServerModule
  OnCreate = UniGUIServerModuleCreate
  OnDestroy = UniGUIServerModuleDestroy
  TempFolder = 'temp\'
  Title = 'IAMClient4D demo'
  BGColorLogin = 11911113
  SuppressErrors = []
  Bindings = <>
  MainFormDisplayMode = mfPage
  CustomCSS.Strings = (
    ':root{'
    
      '  --bs-primary:#0d6efd; --bs-primary-hover:#0b5ed7; --bs-primary' +
      '-border:#0a58ca;'
    
      '  --bs-secondary:#6c757d; --bs-secondary-hover:#5c636a; --bs-sec' +
      'ondary-border:#565e64;'
    
      '  --bs-success:#198754; --bs-success-hover:#157347; --bs-success' +
      '-border:#146c43;'
    
      '  --bs-danger:#dc3545; --bs-danger-hover:#bb2d3b; --bs-danger-bo' +
      'rder:#b02a37;'
    
      '  --bs-warning:#ffc107; --bs-warning-hover:#ffca2c; --bs-warning' +
      '-border:#ffcd39;'
    
      '  --bs-info:#0dcaf0; --bs-info-hover:#31d2f2; --bs-info-border:#' +
      '25cff2;'
    '  --bs-light:#f8f9fa; --bs-dark:#212529;'
    '}'
    ''
    '.mybtn{'
    '  border:1px solid transparent !important;'
    '  border-radius:.5rem !important;'
    
      '  transition:background-color .15s ease, border-color .15s ease,' +
      ' box-shadow .15s ease;'
    '}'
    '.mybtn .x-btn-inner{           '
    '  font-weight:600;'
    '  line-height:1.5;'
    '  padding:.6rem 1.2rem;        '
    '  font-size:14px;'
    '}'
    '.mybtn.x-item-disabled{ opacity:.65; }'
    ''
    '.mybtn:focus-within{'
    '  box-shadow:0 0 0 .25rem rgba(13,110,253,.25);'
    '}'
    ''
    
      '.mybtn-primary{ background-color:var(--bs-primary) !important; b' +
      'order-color:var(--bs-primary) !important; }'
    '.mybtn-primary .x-btn-inner{ color:#fff !important; }'
    
      '.mybtn-primary:hover{ background-color:var(--bs-primary-hover) !' +
      'important; border-color:var(--bs-primary-border) !important; }'
    ''
    
      '.mybtn-secondary{ background-color:var(--bs-secondary) !importan' +
      't; border-color:var(--bs-secondary) !important; }'
    '.mybtn-secondary .x-btn-inner{ color:#fff !important; }'
    
      '.mybtn-secondary:hover{ background-color:var(--bs-secondary-hove' +
      'r) !important; border-color:var(--bs-secondary-border) !importan' +
      't; }'
    ''
    
      '.mybtn-success{ background-color:var(--bs-success) !important; b' +
      'order-color:var(--bs-success) !important; }'
    '.mybtn-success .x-btn-inner{ color:#fff !important; }'
    
      '.mybtn-success:hover{ background-color:var(--bs-success-hover) !' +
      'important; border-color:var(--bs-success-border) !important; }'
    ''
    
      '.mybtn-danger{ background-color:var(--bs-danger) !important; bor' +
      'der-color:var(--bs-danger) !important; }'
    '.mybtn-danger .x-btn-inner{ color:#fff !important; }'
    
      '.mybtn-danger:hover{ background-color:var(--bs-danger-hover) !im' +
      'portant; border-color:var(--bs-danger-border) !important; }'
    ''
    
      '.mybtn-warning{ background-color:var(--bs-warning) !important; b' +
      'order-color:var(--bs-warning) !important; }'
    
      '.mybtn-warning .x-btn-inner{ color:#212529 !important; } /* test' +
      'o scuro su giallo */'
    
      '.mybtn-warning:hover{ background-color:var(--bs-warning-hover) !' +
      'important; border-color:var(--bs-warning-border) !important; }'
    ''
    
      '.mybtn-info{ background-color:var(--bs-info) !important; border-' +
      'color:var(--bs-info) !important; }'
    
      '.mybtn-info .x-btn-inner{ color:#212529 !important; }    /* test' +
      'o scuro su azzurro chiaro */'
    
      '.mybtn-info:hover{ background-color:var(--bs-info-hover) !import' +
      'ant; border-color:var(--bs-info-border) !important; }'
    ''
    
      '.mybtn-light{ background-color:var(--bs-light) !important; borde' +
      'r-color:#ced4da !important; }'
    '.mybtn-light .x-btn-inner{ color:#212529 !important; }'
    
      '.mybtn-light:hover{ background-color:#e9ecef !important; border-' +
      'color:#c7ccd1 !important; }'
    ''
    
      '.mybtn-dark{ background-color:var(--bs-dark) !important; border-' +
      'color:var(--bs-dark) !important; }'
    '.mybtn-dark .x-btn-inner{ color:#fff !important; }'
    
      '.mybtn-dark:hover{ background-color:#1c1f23 !important; border-c' +
      'olor:#1a1e21 !important; }'
    ''
    '.mybtn-lg .x-btn-inner{ font-size:16px; padding:.9rem 1.6rem; }'
    ''
    '/* STATUS BAR */'
    ':root { --sb-nudge: 1px; } '
    ''
    '.mystatus,'
    '.mystatus.x-toolbar,'
    '.mystatus.x-statusbar,'
    '.mystatus.x-toolbar-footer{'
    '  height: 30px !important;              '
    '  padding: 0 !important;'
    '  margin: 0 !important;'
    '  background: #2f3b45 !important;'
    '  color: #e8eef3 !important;'
    '  border-top: 1px solid #242e36 !important;'
    '  box-shadow: none !important;'
    
      '  font: 500 15px/normal system-ui,-apple-system,"Segoe UI",Robot' +
      'o,"Helvetica Neue",Arial,sans-serif !important;'
    '  overflow: hidden;'
    '}'
    ''
    '.mystatus .x-toolbar-ct,'
    '.mystatus .x-box-inner{'
    '  height: 100% !important;'
    '  padding: 0 !important;'
    '  margin: 0 !important;'
    '}'
    ''
    '.mystatus .x-box-target{'
    '  height: 100% !important;'
    '  display: flex !important;'
    '  align-items: center !important;'
    '}'
    ''
    '.mystatus .x-toolbar-text,'
    '.mystatus .x-status-text{'
    '  display: flex !important;'
    '  align-items: center !important;'
    '  height: 100% !important;'
    '  line-height: 1 !important;'
    '  margin: 0 !important;'
    '  padding: 0 12px !important;'
    '  white-space: nowrap;'
    '  color: #e8eef3 !important;'
    '  transform: translateY(var(--sb-nudge));'
    '}'
    ''
    '.mystatus .x-btn,'
    '.mystatus .x-form-field{'
    '  height: 28px !important;'
    '  line-height: 28px !important;'
    '  margin: 0 6px !important;'
    '  align-self: center !important;'
    '}')
  ServerMessages.TerminateTemplate.Strings = (
    '<!DOCTYPE html>'
    '<html lang="it">'
    '  <head>'
    '    <meta charset="utf-8">'
    '    <meta http-equiv="x-ua-compatible" content="ie=edge">'
    
      '    <meta name="viewport" content="width=device-width, initial-s' +
      'cale=1, shrink-to-fit=no">'
    '    <title>IAMClient4D</title>'
    '    <style>'
    '      :root{'
    
      '        --bg:#eef2f5;--fg:#222;--muted:#55606d;--accent:#2498e3;' +
      '--accent-hover:#188dd9;--border:#d9dee5;--highlight:#f47755'
    '      }'
    ''
    '      html{'
    '        color:var(--fg);'
    
      '        font:300 62.5%/1.5 system-ui,-apple-system,"Segoe UI",Ro' +
      'boto,"Helvetica Neue",Arial,sans-serif;'
    '        -webkit-text-size-adjust:100%;'
    '        -ms-text-size-adjust:100%;'
    '        -webkit-tap-highlight-color:transparent;'
    '      }'
    ''
    '      body,html{height:100%;min-height:100%}'
    '      body{'
    '        margin:0;'
    '        background:var(--bg);'
    '        color:var(--fg);'
    '        font-size:1.6rem;'
    '      }'
    ''
    
      '      a{cursor:pointer;text-decoration:none;color:var(--accent);' +
      'background:transparent}'
    
      '      a:hover,a:active{text-decoration:underline;color:var(--acc' +
      'ent-hover);outline:0}'
    ''
    
      '      h1,h2{margin:0 0 .6rem;color:#3c4450;font-weight:500;line-' +
      'height:1.2}'
    '      h1{font-size:2rem} h2{font-size:2.4rem}'
    ''
    '      .error-code{'
    '        color:var(--highlight);'
    '        font-size:3.2rem;'
    '        line-height:1.1;'
    '        font-weight:500;'
    '      }'
    ''
    '      p{margin:1.2rem 0}'
    '      p.lead{font-size:1.4rem;color:var(--muted)}'
    ''
    '      hr{'
    '        box-sizing:content-box;'
    '        height:0;'
    '        margin:2rem 0;'
    '        border:0;'
    '        border-top:1px solid var(--border);'
    '      }'
    ''
    '      .page{display:flex;min-height:100vh}'
    '      .main{'
    '        flex:1 1 70%;'
    '        box-sizing:border-box;'
    '        padding:6rem 3rem 3rem;'
    '        min-height:100vh;'
    '      }'
    ''
    '      /* --- Button stile Bootstrap, versione large --- */'
    '      .btn{'
    '        display:inline-block;'
    '        font-weight:600;'
    '        line-height:1.5;'
    '        text-align:center;'
    '        text-decoration:none;'
    '        vertical-align:middle;'
    '        user-select:none;'
    '        border:1px solid transparent;'
    '        padding:1rem 2rem;            /* pi'#249' grande */'
    '        font-size:1.8rem;             /* pi'#249' grande */'
    '        border-radius:.6rem;'
    
      '        transition:color .15s ease, background-color .15s ease, ' +
      'border-color .15s ease, box-shadow .15s ease;'
    '      }'
    
      '      .btn:disabled,.btn[aria-disabled="true"]{opacity:.65;point' +
      'er-events:none}'
    '      .btn-primary{'
    '        color:#fff;'
    '        background-color:var(--accent);'
    '        border-color:var(--accent);'
    '      }'
    '      .btn-primary:hover{'
    '        color:#fff;'
    '        background-color:var(--accent-hover);'
    '        border-color:var(--accent-hover);'
    '        text-decoration:none;'
    '      }'
    '      .btn-primary:active{'
    '        background-color:#117ec4;'
    '        border-color:#117ec4;'
    '      }'
    '      .btn:focus-visible{'
    '        outline:0;'
    '        box-shadow:0 0 0 .3rem rgba(36,152,227,.35);'
    '      }'
    ''
    '      .help-actions{margin-top:2rem}'
    '      .help-actions .btn{margin-right:.5rem;margin-bottom:.5rem}'
    ''
    '      @media (max-width:480px){'
    '        .main{padding:4rem 1.6rem}'
    '        .error-code{font-size:2.6rem}'
    '        .btn{font-size:1.6rem;padding:.8rem 1.6rem}'
    '      }'
    '    </style>'
    '  </head>'
    '  <body>'
    '    <div class="page">'
    '      <div class="main">'
    
      '        <div class="error-code">User disconnected and session cl' +
      'osed successfully</div>'
    '        <h2></h2>'
    '        <div class="error-description">'
    '          <p class="lead"></p>'
    '          <hr />'
    '        </div>'
    '        <div class="help-actions">'
    
      '          <a class="btn btn-primary" href="javascript:location.r' +
      'eload();" role="button">'
    '            Restart IAMClient4D'
    '          </a>'
    '        </div>'
    '      </div>'
    '    </div>'
    '  </body>'
    '</html>')
  SSL.SSLOptions.RootCertFile = 'root.pem'
  SSL.SSLOptions.CertFile = 'cert.pem'
  SSL.SSLOptions.KeyFile = 'key.pem'
  SSL.SSLOptions.Method = sslvSSLv23
  SSL.SSLOptions.SSLVersions = [sslvTLSv1_1, sslvTLSv1_2]
  SSL.SSLOptions.Mode = sslmUnassigned
  SSL.SSLOptions.VerifyMode = []
  SSL.SSLOptions.VerifyDepth = 0
  ConnectionFailureRecovery.ErrorMessage = 'Connection Error'
  ConnectionFailureRecovery.RetryMessage = 'Retrying...'
  Height = 480
  Width = 640
end
