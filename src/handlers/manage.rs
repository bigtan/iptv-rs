use super::super::*;

#[get("/manage/config")]
pub(crate) async fn manage_config(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
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
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or(std::time::SystemTime::now());
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
    let current_bind = {
        let current = match state.runtime.read() {
            Ok(guard) => guard,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Config lock poisoned");
            }
        };
        if !current.config.manage.enabled {
            return HttpResponse::NotFound().body("Manage disabled");
        }
        if !check_auth(&req, &current.config, "manage") {
            return HttpResponse::Unauthorized().body("Unauthorized");
        }
        current.effective_args.bind.clone()
    };

    let path = match state.config_path.as_ref() {
        Some(path) => path.clone(),
        None => {
            return HttpResponse::BadRequest().body("No config path specified");
        }
    };
    let config = match load_config(Some(&path)) {
        Ok(cfg) => cfg,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let compiled = match compile_config(&config) {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let templates = match build_templates(&config) {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let effective_args = match build_effective_args(&state.cli_args, &config) {
        Ok(args) => args,
        Err(e) => return HttpResponse::BadRequest().body(format!("Error: {e}")),
    };
    if effective_args.bind != current_bind {
        return HttpResponse::Conflict()
            .body("Bind address changed; restart the service to apply this configuration");
    }
    let response_config = {
        let mut runtime = match state.runtime.write() {
            Ok(guard) => guard,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Config lock poisoned");
            }
        };
        runtime.config = config;
        runtime.compiled = compiled;
        runtime.templates = templates;
        runtime.effective_args = effective_args;
        runtime.config.clone()
    };
    if let Ok(mut cache) = state.playlist_cache.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.xmltv_cache.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.manage_json_cache.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.manage_html_cache.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.manage_raw_cache.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.stale_playlists.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = state.stale_xmltv.lock() {
        cache.clear();
    }
    state.upstream_cache.lock().await.clear();
    state.icon_cache.lock().await.clear();
    state.upstream_flights.lock().await.clear();
    state.icon_flights.lock().await.clear();
    with_auth_cookie(
        &req,
        &response_config,
        "manage",
        HttpResponse::Ok().body("OK"),
    )
}

#[get("/manage/test")]
pub(crate) async fn manage_test(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let name = match params.get("name") {
        Some(v) => v.to_string(),
        None => return HttpResponse::BadRequest().body("Missing name"),
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
    let (enabled, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.manage.enabled,
            check_auth(&req, &guard.config, "manage"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let is_kodi = user_agent.to_lowercase().contains("kodi");
    let playseek = if is_kodi {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let output_args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let cache_key = format!(
        "{}|{}|{}|{}|{}",
        scheme,
        host,
        is_kodi,
        output_args.fcc_enabled,
        limit.unwrap_or(usize::MAX)
    );
    if let Some(text) = get_cached_text(&state.manage_json_cache, &cache_key) {
        let runtime = match state.runtime.read() {
            Ok(guard) => guard,
            Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
        };
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("application/json")
                .body(text),
        );
    }
    let channels = match get_channels_cached(&state, &output_args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let mut entries =
        build_local_entries(channels, &output_args, &scheme, &host, playseek, 0, limit);
    if !output_args.extra_playlist.is_empty() && limit.is_none_or(|limit| entries.len() < limit) {
        let mut index = entries.len();
        for (source_index, content) in
            fetch_extra_playlists(&state.extra_client, &output_args.extra_playlist).await
        {
            let source = format!("extra:{source_index}");
            let mut extra_entries = parse_m3u_playlist(&content, &source, index);
            if let Some(limit) = limit {
                let remaining = limit.saturating_sub(entries.len());
                extra_entries.truncate(remaining);
            }
            index += extra_entries.len();
            entries.append(&mut extra_entries);
            if limit.is_some_and(|limit| entries.len() >= limit) {
                break;
            }
        }
    }
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    protect_local_entry_urls(&mut entries, &runtime.config);
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }
    match serde_json::to_string_pretty(&entries) {
        Ok(text) => {
            put_cached_text(
                &state.manage_json_cache,
                cache_key,
                text.clone(),
                MANAGE_CACHE_TTL,
            );
            with_auth_cookie(
                &req,
                &runtime.config,
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
    let (enabled, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.manage.enabled,
            check_auth(&req, &guard.config, "manage"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let cache_key = String::from("raw");
    if let Some(text) = get_cached_text(&state.manage_raw_cache, &cache_key) {
        let runtime = match state.runtime.read() {
            Ok(guard) => guard,
            Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
        };
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
    let output_args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {e}")),
    };
    let text = match get_channel_list_raw(&output_args).await {
        Ok(text) => text,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    put_cached_text(
        &state.manage_raw_cache,
        cache_key,
        text.clone(),
        MANAGE_CACHE_TTL,
    );
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    with_auth_cookie(
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
    )
}

#[get("/manage/channels/html")]
pub(crate) async fn manage_channels_html(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let (enabled, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.manage.enabled,
            check_auth(&req, &guard.config, "manage"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let is_kodi = user_agent.to_lowercase().contains("kodi");
    let playseek = if is_kodi {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let output_args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let cache_key = format!(
        "{}|{}|{}|{}|{}",
        scheme,
        host,
        is_kodi,
        output_args.fcc_enabled,
        limit.unwrap_or(usize::MAX)
    );
    if let Some(html) = get_cached_text(&state.manage_html_cache, &cache_key) {
        let runtime = match state.runtime.read() {
            Ok(guard) => guard,
            Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
        };
        return with_auth_cookie(
            &req,
            &runtime.config,
            "manage",
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(html),
        );
    }
    let channels = match get_channels_cached(&state, &output_args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let mut entries =
        build_local_entries(channels, &output_args, &scheme, &host, playseek, 0, limit);
    if !output_args.extra_playlist.is_empty() && limit.is_none_or(|limit| entries.len() < limit) {
        let mut index = entries.len();
        for (source_index, content) in
            fetch_extra_playlists(&state.extra_client, &output_args.extra_playlist).await
        {
            let source = format!("extra:{source_index}");
            let mut extra_entries = parse_m3u_playlist(&content, &source, index);
            if let Some(limit) = limit {
                let remaining = limit.saturating_sub(entries.len());
                extra_entries.truncate(remaining);
            }
            index += extra_entries.len();
            entries.append(&mut extra_entries);
            if limit.is_some_and(|limit| entries.len() >= limit) {
                break;
            }
        }
    }
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    protect_local_entry_urls(&mut entries, &runtime.config);
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }

    let html = super::views::render_channels(&entries, limit);
    put_cached_text(
        &state.manage_html_cache,
        cache_key,
        html.clone(),
        MANAGE_CACHE_TTL,
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

#[get("/status")]
pub(crate) async fn status(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let need_auth = match state.runtime.read() {
        Ok(guard) => check_auth(&req, &guard.config, "status"),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or(std::time::SystemTime::now());
    let uptime = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);

    let channels_link = String::from("/manage/channels?limit=200");

    let (
        alias_preview,
        group_pills,
        group_count,
        alias_rules,
        protected,
        token_set,
        manage_enabled,
        config_path,
    ) = match state.runtime.read() {
        Ok(guard) => {
            let alias_preview = guard
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
            let group_pills = guard
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
            (
                alias_preview,
                group_pills,
                guard.config.groups.entries.len(),
                guard.config.alias.rules.len(),
                if guard.config.auth.protect.is_empty() {
                    String::from("none")
                } else {
                    guard.config.auth.protect.join(", ")
                },
                if guard.config.auth.token.is_empty() {
                    "no"
                } else {
                    "yes"
                },
                if guard.config.manage.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                state
                    .config_path
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
            )
        }
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let output_args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let channels_count =
        match get_channels_cached(&state, &output_args, false, &scheme, &host).await {
            Ok(ch) => ch.len(),
            Err(_) => 0,
        };
    let html = super::views::render_status(
        uptime,
        &config_path,
        manage_enabled,
        &protected,
        token_set,
        output_args.extra_playlist.len(),
        output_args.extra_xmltv.len(),
        channels_count,
        alias_rules,
        &alias_preview,
        &group_pills,
        group_count,
        &channels_link,
    );
    let config = match state.runtime.read() {
        Ok(guard) => guard.config.clone(),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    with_auth_cookie(
        &req,
        &config,
        "status",
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
    )
}
