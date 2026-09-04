use super::super::*;

pub(super) fn render_manage_index(uptime: u64, alias_rules: usize, group_count: usize) -> String {
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Manage Dashboard</title>
  <style>{base_css}</style>
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); transition: transform 0.2s; }}
    .card:hover {{ transform: translateY(-3px); }}
    .action-icon {{ width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link" href="/status">Status</a>
        <a class="nav-link active" href="/manage">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row mb-4">
      <div class="col">
        <h2 class="fw-bold">Management Dashboard</h2>
        <p class="text-muted">Control and monitor your IPTV proxy settings.</p>
      </div>
    </div>

    <div class="row g-4 mb-5">
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-primary text-white"><i class="bi bi-file-earmark-code"></i></div>
          <h5 class="fw-bold">View Configuration</h5>
          <p class="small text-muted flex-grow-1">Inspect the current active TOML configuration and runtime parameters.</p>
          <a href="/manage/config" class="btn btn-outline-primary btn-sm mt-3">Open Config</a>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-success text-white"><i class="bi bi-arrow-clockwise"></i></div>
          <h5 class="fw-bold">Hot Reload</h5>
          <p class="small text-muted flex-grow-1">Reload the configuration file from disk without restarting the service.</p>
          <form method="post" action="/manage/reload" class="mt-3">
            <button type="submit" class="btn btn-outline-success btn-sm">Reload Now</button>
          </form>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-info text-white"><i class="bi bi-search"></i></div>
          <h5 class="fw-bold">Test Rules</h5>
          <p class="small text-muted flex-grow-1">Verify alias and grouping rules against specific channel names.</p>
          <a href="/manage/test?name=CCTV1" class="btn btn-outline-info btn-sm mt-3">Try Example</a>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-warning text-dark"><i class="bi bi-list-stars"></i></div>
          <h5 class="fw-bold">Channel List</h5>
          <p class="small text-muted flex-grow-1">Browse all discovered channels with applied alias and resolution info.</p>
          <div class="d-flex gap-2 mt-3">
            <a href="/manage/channels/html?limit=200" class="btn btn-warning btn-sm">Interactive UI</a>
            <a href="/manage/channels?limit=200" class="btn btn-outline-warning btn-sm">JSON</a>
            <a href="/manage/channels/raw" class="btn btn-outline-dark btn-sm">Raw</a>
          </div>
        </div>
      </div>
    </div>

    <div class="card bg-white p-4">
      <h5 class="mb-4 fw-bold"><i class="bi bi-info-circle me-2"></i>Runtime Summary</h5>
      <div class="row g-4 text-center">
        <div class="col-sm-4">
          <div class="border-end">
            <div class="text-muted small text-uppercase fw-bold mb-1">Uptime</div>
            <div class="fw-bold h4 mb-0 text-primary">{uptime}s</div>
          </div>
        </div>
        <div class="col-sm-4">
          <div class="border-end">
            <div class="text-muted small text-uppercase fw-bold mb-1">Alias Rules</div>
            <div class="fw-bold h4 mb-0 text-primary">{alias_rules}</div>
          </div>
        </div>
        <div class="col-sm-4">
          <div>
            <div class="text-muted small text-uppercase fw-bold mb-1">Groups</div>
            <div class="fw-bold h4 mb-0 text-primary">{group_count}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="mt-5 p-4 bg-light rounded-3 border">
      <h6 class="fw-bold mb-2">Access Tip</h6>
      <p class="small text-muted mb-0">If security tokens are enabled, prefer the <code>Authorization: Bearer ...</code> or <code>X-Api-Token</code> headers. Query tokens are accepted but are not echoed back into management links.</p>
    </div>
  </div>
</body>
</html>"#,
        uptime = uptime,
        alias_rules = alias_rules,
        group_count = group_count,
        base_css = BASE_CSS,
    );
    html
}

pub(super) fn render_channels(entries: &[ChannelEntry], limit: Option<usize>) -> String {
    let count = entries.len();
    let limit = limit.unwrap_or(entries.len());

    let mut rows = String::with_capacity(entries.len().saturating_mul(256));
    for e in entries.iter() {
        let alias_name = html_escape(&e.alias_name);
        let raw_name = html_escape(&e.raw_name);
        let group = html_escape(&e.group);
        let resolution_label = html_escape(&e.resolution_label);
        let url = html_escape(&e.url);
        rows.push_str(&format!(
            "<tr><td class='fw-bold text-primary'>{}</td><td class='text-muted small'>{}</td><td><span class='badge bg-light text-dark border'>{}</span></td><td><span class='badge bg-info-subtle text-info border border-info-subtle'>{}</span></td><td class='url-cell text-truncate' style='max-width:250px;'><a href='{}' class='text-decoration-none small' title='{}'>{}</a></td></tr>\n",
            alias_name,
            raw_name,
            group,
            resolution_label,
            url,
            url,
            url,
        ));
    }

    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Channel List - IPTV Proxy</title>
  <style>{base_css}</style>
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); }}
    .table thead th {{ background-color: #f8f9fa; border-top: none; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; color: #6c757d; padding: 12px 16px; }}
    .table td {{ vertical-align: middle; padding: 12px 16px; font-size: 0.9rem; }}
    .search-wrap {{ position: relative; }}
    .search-wrap i {{ position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: #6c757d; }}
    .search-wrap input {{ padding-left: 36px; border-radius: 10px; border-color: #e3e7ef; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link" href="/status">Status</a>
        <a class="nav-link active" href="/manage">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row align-items-center mb-4 g-3">
      <div class="col-md-6">
        <h2 class="fw-bold mb-0">Channels</h2>
        <p class="text-muted mb-0 small">Browsing {count} discovered channels</p>
      </div>
      <div class="col-md-6">
        <div class="search-wrap">
          <i class="bi bi-search"></i>
          <input type="text" id="searchInput" class="form-control" placeholder="Search by name, alias or group...">
        </div>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div class="table-responsive">
        <table class="table table-hover mb-0" id="channelTable">
          <thead>
            <tr>
              <th>Alias Name</th>
              <th>Original Name</th>
              <th>Group</th>
              <th>Res</th>
              <th>URL / Source</th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
    </div>

    <div class="mt-4 d-flex justify-content-between align-items-center">
      <div class="small text-muted">
        Showing up to {limit} entries. Use <code>?limit=N</code> to change.
      </div>
      <div>
        <a href="/manage/channels" class="btn btn-outline-secondary btn-sm"><i class="bi bi-filetype-json me-1"></i>Export JSON</a>
        <a href="/manage/channels/raw" class="btn btn-outline-primary btn-sm ms-2"><i class="bi bi-download me-1"></i>Download Raw</a>
      </div>
    </div>
  </div>

  <script>
    document.getElementById('searchInput').addEventListener('keyup', function() {{
      const searchText = this.value.toLowerCase();
      const rows = document.querySelectorAll('#channelTable tbody tr');

      rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchText) ? '' : 'none';
      }});
    }});
  </script>
</body>
</html>"#,
        rows = rows,
        count = count,
        limit = limit,
        base_css = BASE_CSS,
    );
    html
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_status(
    uptime: u64,
    config_path: &str,
    manage_enabled: &str,
    protected: &str,
    token_set: &str,
    extra_playlist: usize,
    extra_xmltv: usize,
    channels_count: usize,
    alias_rules: usize,
    alias_preview: &str,
    group_pills: &str,
    group_count: usize,
    channels_link: &str,
) -> String {
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPTV Proxy Status</title>
  <style>{base_css}</style>
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); }}
    .stat-icon {{ width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px; }}
    .bg-primary-light {{ background-color: rgba(13, 110, 253, 0.1); color: #0d6efd; }}
    .bg-success-light {{ background-color: rgba(25, 135, 84, 0.1); color: #198754; }}
    .bg-info-light {{ background-color: rgba(13, 202, 240, 0.1); color: #0dcaf0; }}
    .bg-warning-light {{ background-color: rgba(255, 193, 7, 0.1); color: #ffc107; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link active" href="/status">Status</a>
        <a class="nav-link" href="/manage">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row g-3 mb-4">
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-success-light me-3"><i class="bi bi-cpu"></i></div>
            <div class="text-muted small text-uppercase fw-bold">System</div>
          </div>
          <div class="h4 mb-1">Running</div>
          <div class="small text-success">Uptime: {uptime}s</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-primary-light me-3"><i class="bi bi-tv"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Channels</div>
          </div>
          <div class="h4 mb-1">{channels_count}</div>
          <div class="small"><a href="{channels_link}" class="text-decoration-none">Explore All <i class="bi bi-arrow-right"></i></a></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-info-light me-3"><i class="bi bi-shield-lock"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Auth</div>
          </div>
          <div class="h4 mb-1">{token_set}</div>
          <div class="small text-muted text-truncate" title="{protected}">Protect: {protected}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-warning-light me-3"><i class="bi bi-gear"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Config</div>
          </div>
          <div class="h4 mb-1">{manage_enabled}</div>
          <div class="small text-muted text-truncate" title="{config_path}">{config_path}</div>
        </div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-8">
        <div class="card mb-4">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Functional Endpoints</h5></div>
          <div class="card-body">
            <div class="list-group list-group-flush">
              <a href="/playlist" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">M3U Playlist</div><div class="small text-muted">Aggregated playlist with alias and sorting</div></div>
                <span class="badge bg-primary rounded-pill">/playlist</span>
              </a>
              <a href="/xmltv" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">XMLTV EPG</div><div class="small text-muted">Electronic Program Guide data</div></div>
                <span class="badge bg-primary rounded-pill">/xmltv</span>
              </a>
              <div class="list-group-item d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">Extra Sources</div><div class="small text-muted">Additional M3U/XMLTV from CLI args</div></div>
                <div>
                  <span class="badge bg-secondary me-1">{extra_playlist} Playlists</span>
                  <span class="badge bg-secondary">{extra_xmltv} EPGs</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Alias Rules Preview <span class="badge bg-light text-muted fw-normal ms-2">{alias_rules} total</span></h5></div>
          <div class="card-body">
            <div class="small">{alias_preview}</div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card mb-4">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Channel Groups <span class="badge bg-light text-muted fw-normal ms-2">{group_count} total</span></h5></div>
          <div class="card-body">
            <div class="d-flex flex-wrap">{group_pills}</div>
          </div>
        </div>
        <div class="card">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Quick Links</h5></div>
          <div class="card-body">
            <ul class="list-unstyled mb-0">
              <li class="mb-2"><a href="/manage" class="text-decoration-none"><i class="bi bi-speedometer2 me-2"></i>Management Dashboard</a></li>
              <li class="mb-2"><a href="/manage/config" class="text-decoration-none"><i class="bi bi-file-earmark-code me-2"></i>View Raw Config</a></li>
              <li class="mb-2"><a href="/manage/channels/raw" class="text-decoration-none"><i class="bi bi-download me-2"></i>Download Raw ChannelList</a></li>
              <li><a href="/manage/channels/html" class="text-decoration-none"><i class="bi bi-list-ul me-2"></i>Interactive Channel List</a></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        uptime = uptime,
        config_path = config_path,
        manage_enabled = manage_enabled,
        protected = protected,
        token_set = if token_set == "yes" { "Active" } else { "None" },
        extra_playlist = extra_playlist,
        extra_xmltv = extra_xmltv,
        channels_count = channels_count,
        alias_rules = alias_rules,
        alias_preview = alias_preview,
        group_pills = group_pills,
        group_count = group_count,
        channels_link = channels_link,
        base_css = BASE_CSS,
    );
    html
}
