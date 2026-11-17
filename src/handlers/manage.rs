use crate::{
    AppState, ManageTestResult, ReloadError, START_TIME, build_local_entries, check_auth,
    get_channel_list_raw, get_channels_cached, html_escape,
    playlist::{
        EntryBuildContext, add_alias_and_resolution_for_name, finalize_entries,
        resolve_group_for_alias,
    },
    protect_local_entry_urls, redacted_config, reload_runtime_config, with_auth_cookie,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    http::header,
    post,
    web::{Data, Query},
};
use std::collections::BTreeMap;

#[get("/manage/config")]
pub(crate) async fn manage_config(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let safe = redacted_config(&runtime.config);
    match toml::to_string_pretty(&safe) {
        Ok(text) => with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("text/plain; charset=utf-8")
                .body(text),
        ),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage")]
pub(crate) async fn manage_index(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or_else(std::time::SystemTime::now);
    let uptime = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let html = super::views::render_manage_index(
        uptime,
        runtime.config.alias.rules.len(),
        runtime.config.groups.entries.len(),
    );
    with_auth_cookie(
        &req,
        &runtime.config,
        "manage",
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
    )
}

#[post("/manage/reload")]
pub(crate) async fn manage_reload(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let current = state.runtime();
    if !current.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &current.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    match reload_runtime_config(&state) {
        Ok(next) => with_auth_cookie(&req, &next.config, "manage", HttpResponse::Ok().body("OK")),
        Err(ReloadError::NoConfigPath) => {
            HttpResponse::BadRequest().body("No config path specified")
        }
        Err(ReloadError::InvalidArgs(e)) => HttpResponse::BadRequest().body(format!("Error: {e}")),
        Err(ReloadError::ListenerChanged(msg)) => HttpResponse::Conflict().body(msg),
        Err(ReloadError::LoadOrCompile(e)) => {
            HttpResponse::InternalServerError().body(format!("Error: {e}"))
        }
    }
}

#[get("/manage/test")]
pub(crate) async fn manage_test(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let Some(name) = params.get("name").cloned() else {
        return HttpResponse::BadRequest().body("Missing name");
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let (alias, score, label) = add_alias_and_resolution_for_name(&name, &ctx);
    let group = resolve_group_for_alias(
        &alias,
        &runtime.compiled,
        &runtime.config.groups.default_group,
    );
    let res = ManageTestResult {
        input: name,
        alias_name: alias,
        resolution_score: score,
        resolution_label: label,
        group,
    };
    match serde_json::to_string_pretty(&res) {
        Ok(text) => with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("application/json")
                .body(text),
        ),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels")]
pub(crate) async fn manage_channels(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    if runtime.effective_args.upstream.is_none() {
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("application/json")
                .body("[]"),
        );
    }

    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let is_kodi = user_agent.to_ascii_lowercase().contains("kodi");
    let playseek = if is_kodi {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let output_args = &runtime.effective_args;
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let cache_key = format!(
        "{scheme}|{host}|{is_kodi}|{}|{}|{}|{}",
        output_args.udp_proxy,
        output_args.rtsp_proxy,
        output_args.fcc_enabled,
        limit.unwrap_or(usize::MAX)
    );
    if let Some(text) = state.caches.get_manage_json(&cache_key) {
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("application/json")
                .body(text),
        );
    }

    let expected_gen = state.caches.generation();
    let channels = match get_channels_cached(&state, output_args, false).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let live = state.runtime();
    let mut entries = build_local_entries(
        channels,
        &live.effective_args,
        &scheme,
        &host,
        playseek,
        0,
        limit,
    );
    let ctx = EntryBuildContext {
        config: &live.config,
        compiled: &live.compiled,
    };
    protect_local_entry_urls(&mut entries, &live.config);
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }
    match serde_json::to_string_pretty(&entries) {
        Ok(text) => {
            state
                .caches
                .put_manage_json(expected_gen, cache_key, text.clone());
            with_auth_cookie(
                &req,
                &live.config,
                "manage",
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(text),
            )
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels/raw")]
pub(crate) async fn manage_channels_raw(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let Some(creds) = runtime.effective_args.upstream.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .body("Raw channel list is unavailable in proxy-only mode (no upstream credentials)");
    };

    let cache_key = String::from("raw");
    if let Some(text) = state.caches.get_manage_raw(&cache_key) {
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
                .insert_header((
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"channellist-raw.txt\"",
                ))
                .body(text),
        );
    }

    let expected_gen = state.caches.generation();
    let text = match get_channel_list_raw(
        &state.upstream_auth,
        creds,
        runtime.effective_args.interface.as_deref(),
    )
    .await
    {
        Ok(text) => text,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    state
        .caches
        .put_manage_raw(expected_gen, cache_key, text.clone());
    let live = state.runtime();
    with_auth_cookie(
        &req,
        &live.config,
        "manage",
        HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
            .insert_header((
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"channellist-raw.txt\"",
            ))
            .body(text),
    )
}

#[get("/manage/channels/html")]
pub(crate) async fn manage_channels_html(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let runtime = state.runtime();
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    if runtime.effective_args.upstream.is_none() {
        let html = super::views::render_channels(&[], limit);
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(html),
        );
    }

    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let is_kodi = user_agent.to_ascii_lowercase().contains("kodi");
    let playseek = if is_kodi {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let output_args = &runtime.effective_args;
    let cache_key = format!(
        "{scheme}|{host}|{is_kodi}|{}|{}|{}|{}",
        output_args.udp_proxy,
        output_args.rtsp_proxy,
        output_args.fcc_enabled,
        limit.unwrap_or(usize::MAX)
    );
    if let Some(html) = state.caches.get_manage_html(&cache_key) {
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(html),
        );
    }

    let expected_gen = state.caches.generation();
    let channels = match get_channels_cached(&state, output_args, false).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let live = state.runtime();
    let mut entries = build_local_entries(
        channels,
        &live.effective_args,
        &scheme,
        &host,
        playseek,
        0,
        limit,
    );
    let ctx = EntryBuildContext {
        config: &live.config,
        compiled: &live.compiled,
    };
    protect_local_entry_urls(&mut entries, &live.config);
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }

    let html = super::views::render_channels(&entries, limit);
    state
        .caches
        .put_manage_html(expected_gen, cache_key, html.clone());
    with_auth_cookie(
        &req,
        &live.config,
        "manage",
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
    )
}

#[get("/status")]
pub(crate) async fn status(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = state.runtime();
    if !check_auth(&req, &runtime.config, "status") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or_else(std::time::SystemTime::now);
    let uptime = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);

    let channels_link = String::from("/manage/channels?limit=200");

    let alias_preview = runtime
        .config
        .alias
        .rules
        .iter()
        .take(10)
        .enumerate()
        .map(|(i, r)| {
            format!(
                "<div class='mb-2 d-flex align-items-center'><span class='badge bg-light text-dark me-2'>{}</span> <code class='text-truncate'>{}</code> <i class='bi bi-arrow-right mx-2 text-muted'></i> <code class='text-truncate'>{}</code></div>",
                i + 1,
                html_escape(&r.pattern),
                html_escape(&r.replace)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let group_pills = runtime
        .config
        .groups
        .entries
        .iter()
        .map(|g| {
            format!(
                "<span class='badge bg-primary-subtle text-primary border border-primary-subtle me-1 mb-1'>{}</span>",
                html_escape(&g.group)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let group_count = runtime.config.groups.entries.len();
    let alias_rules = runtime.config.alias.rules.len();
    let protected = if runtime.config.auth.protect.is_empty() {
        String::from("none")
    } else {
        runtime.config.auth.protect.join(", ")
    };
    let token_set = if runtime.config.auth.token.is_empty() {
        "no"
    } else {
        "yes"
    };
    let manage_enabled = if runtime.config.manage.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let config_path = state
        .config_path
        .clone()
        .unwrap_or_else(|| "default".to_string());

    let channels_count = match get_channels_cached(&state, &runtime.effective_args, false).await {
        Ok(ch) => ch.len(),
        Err(_) => 0,
    };
    let html = super::views::render_status(
        uptime,
        &config_path,
        manage_enabled,
        &protected,
        token_set,
        channels_count,
        alias_rules,
        &alias_preview,
        &group_pills,
        group_count,
        &channels_link,
    );
    let live = state.runtime();
    with_auth_cookie(
        &req,
        &live.config,
        "status",
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
    )
}
