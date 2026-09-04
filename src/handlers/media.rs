use super::super::*;

#[get("/xmltv")]
pub(crate) async fn xmltv(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get EPG");
    let (use_alias_name, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.xmltv.use_alias_name,
            check_auth(&req, &guard.config, "xmltv"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let output_args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let cache_key = format!("{}|{}|{}", scheme, host, output_args.fcc_enabled);
    if let Some(xml) = get_cached_text(&state.xmltv_cache, &cache_key) {
        return HttpResponse::Ok().content_type("text/xml").body(xml);
    }
    // parse all extra xmltv URLs in parallel using JoinSet, collect successful readers
    let extra_readers = if !output_args.extra_xmltv.is_empty() {
        let mut set = JoinSet::new();
        for (i, u) in output_args.extra_xmltv.iter().enumerate() {
            let u = u.clone();
            let client = state.extra_client.clone();
            set.spawn(async move { (i, parse_extra_xml(&client, &u).await) });
        }
        let mut readers = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((i, Ok(reader))) => readers.push((i, reader)),
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra xmltv ({}): {}",
                    output_args.extra_xmltv[i], e
                ),
                Err(e) => warn!("Task join error parsing extra xmltv: {}", e),
            }
        }
        readers.sort_by_key(|(index, _)| *index);
        readers.into_iter().map(|(_, reader)| reader).collect()
    } else {
        Vec::new()
    };
    let xml = get_channels_cached(&state, &output_args, true, &scheme, &host)
        .await
        .and_then(|mut ch| {
            if use_alias_name {
                let runtime = match state.runtime.read() {
                    Ok(guard) => guard,
                    Err(_) => return Err(anyhow!("Config lock poisoned")),
                };
                for channel in ch.iter_mut() {
                    let alias = apply_alias(&channel.name, &runtime.config, &runtime.compiled);
                    let alias = alias.trim().to_string();
                    if !alias.is_empty() {
                        channel.name = alias;
                    }
                }
            }
            to_xmltv(ch, extra_readers)
        });
    match xml {
        Err(e) => {
            if let Some(old_xmltv) = state
                .stale_xmltv
                .lock()
                .ok()
                .and_then(|cache| cache.get(&cache_key).cloned())
            {
                HttpResponse::Ok().content_type("text/xml").body(old_xmltv)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(xml) => {
            put_cached_text(
                &state.xmltv_cache,
                cache_key.clone(),
                xml.clone(),
                XMLTV_CACHE_TTL,
            );
            put_stale_text(&state.stale_xmltv, cache_key, xml.clone());
            HttpResponse::Ok().content_type("text/xml").body(xml)
        }
    }
}

#[get("/logo/{id}.png")]
pub(crate) async fn logo(
    state: Data<AppState>,
    path: Path<String>,
    req: HttpRequest,
) -> impl Responder {
    debug!("Get logo");
    match state.runtime.read() {
        Ok(guard) if !check_auth(&req, &guard.config, "logo") => {
            return HttpResponse::Unauthorized().body("Unauthorized");
        }
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
        _ => {}
    }
    let args = match output_effective_args(&state) {
        Ok(args) => args,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {e}")),
    };
    match get_icon_cached(&state, &args, &path).await {
        Ok(icon) => HttpResponse::Ok().content_type("image/png").body(icon),
        Err(e) => HttpResponse::NotFound().body(format!("Error getting channels: {}", e)),
    }
}

#[get("/playlist")]
pub(crate) async fn playlist_handler(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get playlist");
    let need_auth = match state.runtime.read() {
        Ok(guard) => check_auth(&req, &guard.config, "playlist"),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
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
    let cache_key = format!(
        "{}|{}|{}|{}",
        scheme, host, is_kodi, output_args.fcc_enabled
    );
    if let Some(playlist) = get_cached_text(&state.playlist_cache, &cache_key) {
        return HttpResponse::Ok()
            .content_type("application/vnd.apple.mpegurl")
            .body(playlist);
    }
    match get_channels_cached(&state, &output_args, false, &scheme, &host).await {
        Err(e) => {
            if let Some(old_playlist) = state
                .stale_playlists
                .lock()
                .ok()
                .and_then(|cache| cache.get(&cache_key).cloned())
            {
                HttpResponse::Ok()
                    .content_type("application/vnd.apple.mpegurl")
                    .body(old_playlist)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(ch) => {
            let mut entries =
                build_local_entries(ch, &output_args, &scheme, &host, playseek, 0, None);
            if !output_args.extra_playlist.is_empty() {
                let mut index = entries.len();
                for (source_index, content) in
                    fetch_extra_playlists(&state.extra_client, &output_args.extra_playlist).await
                {
                    let source = format!("extra:{source_index}");
                    let mut extra_entries = parse_m3u_playlist(&content, &source, index);
                    index += extra_entries.len();
                    entries.append(&mut extra_entries);
                }
            }

            let runtime = match state.runtime.read() {
                Ok(guard) => guard,
                Err(_) => {
                    return HttpResponse::InternalServerError().body("Config lock poisoned");
                }
            };
            let ctx = EntryBuildContext {
                config: &runtime.config,
                compiled: &runtime.compiled,
            };
            protect_local_entry_urls(&mut entries, &runtime.config);
            let entries = finalize_entries(entries, &ctx);
            let playlist = match render_playlist(&entries, &runtime.templates) {
                Ok(playlist) => playlist,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Template render error: {}", e));
                }
            };
            put_cached_text(
                &state.playlist_cache,
                cache_key.clone(),
                playlist.clone(),
                PLAYLIST_CACHE_TTL,
            );
            put_stale_text(&state.stale_playlists, cache_key, playlist.clone());
            HttpResponse::Ok()
                .content_type("application/vnd.apple.mpegurl")
                .body(playlist)
        }
    }
}

#[get("/rtsp/{tail:.*}")]
pub(crate) async fn rtsp(
    state: Data<AppState>,
    mut params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    let effective_args = match state.runtime.read() {
        Ok(guard) => {
            if !guard.effective_args.rtsp_proxy {
                return HttpResponse::NotFound().body("RTSP proxy disabled");
            }
            if !check_auth(&req, &guard.config, "rtsp") {
                return HttpResponse::Unauthorized().body("Unauthorized");
            }
            guard.effective_args.clone()
        }
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let path: String = req.match_info().query("tail").into();
    if !params.contains_key("playseek") && params.contains_key("utc") {
        let Some(utc) = params.get("utc") else {
            return HttpResponse::BadRequest().body("Missing utc");
        };
        let start = match utc.parse::<i64>() {
            Ok(utc) => match to_xmltv_time(utc * 1000) {
                Ok(start) => start,
                Err(_) => return HttpResponse::BadRequest().body("Invalid utc"),
            },
            Err(_) => return HttpResponse::BadRequest().body("Invalid utc"),
        };
        let end = match params.get("lutc") {
            Some(lutc) => match lutc.parse::<i64>() {
                Ok(lutc) => match to_xmltv_time(lutc * 1000) {
                    Ok(end) => end,
                    Err(_) => return HttpResponse::BadRequest().body("Invalid lutc"),
                },
                Err(_) => return HttpResponse::BadRequest().body("Invalid lutc"),
            },
            None => match to_xmltv_time(Local::now().timestamp_millis()) {
                Ok(end) => end,
                Err(_) => {
                    return HttpResponse::InternalServerError().body("Failed to format local time");
                }
            },
        };
        params.insert("playseek".to_string(), format!("{}-{}", start, end));
    }
    // `token` authenticates this HTTP hop and must never be forwarded to the
    // upstream RTSP server.
    params.remove("token");
    let mut target = match reqwest::Url::parse(&format!("rtsp://{}", path)) {
        Ok(url) => url,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid RTSP target: {e}")),
    };
    if !params.is_empty() {
        let mut pairs = target.query_pairs_mut();
        for (key, value) in params.iter() {
            pairs.append_pair(key, value);
        }
    }
    if let Err(error) = state.upstream_auth.ensure_fresh(&effective_args).await {
        warn!("Pre-stream upstream authorization refresh failed: {error}");
    }
    let permit = match state.shared_proxy.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return HttpResponse::ServiceUnavailable().body("Too many active proxy streams"),
    };
    let target_url = target.to_string();
    match proxy::rtsp_source(target_url.clone(), effective_args.interface.clone(), permit).await {
        Ok(stream) => HttpResponse::Ok()
            .content_type("video/mp2t")
            .streaming(stream),
        Err(error) if is_rtsp_auth_status(&error) => {
            warn!("RTSP authorization rejected; refreshing upstream authorization once");
            if let Err(refresh_error) = state.upstream_auth.force_refresh(&effective_args).await {
                return HttpResponse::BadGateway().body(format!(
                    "RTSP authorization failed and refresh failed: {refresh_error}"
                ));
            }
            let permit = match state.shared_proxy.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable()
                        .body("Too many active proxy streams");
                }
            };
            match proxy::rtsp_source(target_url, effective_args.interface, permit).await {
                Ok(stream) => HttpResponse::Ok()
                    .content_type("video/mp2t")
                    .streaming(stream),
                Err(retry_error) => HttpResponse::BadGateway().body(format!(
                    "RTSP setup failed after authorization refresh: {retry_error}"
                )),
            }
        }
        Err(e) => HttpResponse::BadGateway().body(format!("RTSP setup failed: {e}")),
    }
}

async fn udp_like(
    state: Data<AppState>,
    addr: Path<String>,
    params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    let effective_args = match state.runtime.read() {
        Ok(guard) => {
            if !guard.effective_args.udp_proxy {
                return HttpResponse::NotFound().body("UDP proxy disabled");
            }
            if !check_auth(&req, &guard.config, "udp") {
                return HttpResponse::Unauthorized().body("Unauthorized");
            }
            guard.effective_args.clone()
        }
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let addr = &*addr;
    let addr = match SocketAddrV4::from_str(addr) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Error: {}", e)),
    };
    if let Err(error) = state.upstream_auth.ensure_fresh(&effective_args).await {
        warn!("Pre-stream upstream authorization refresh failed: {error}");
    }
    let fcc = match params.get("fcc") {
        Some(value) => {
            // Read FCC tuning from the live config when a new shared UDP source
            // is created.
            let fcc_cfg = match state.runtime.read() {
                Ok(guard) => guard.config.fcc.clone(),
                Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
            };
            match parse_fcc_server(value) {
                Ok(server) if fcc_cfg.enabled => {
                    debug!(
                        "Parsed FCC query for multicast {}: server={}, max_redirects={}, switch_extra_packets={}, switch_min_unicast_ms={}",
                        addr,
                        server,
                        fcc_cfg.max_redirects,
                        fcc_cfg.switch_extra_packets,
                        fcc_cfg.switch_min_unicast_ms
                    );
                    Some(FccOptions {
                        server,
                        max_redirects: fcc_cfg.max_redirects,
                        switch_extra_packets: fcc_cfg.switch_extra_packets,
                        switch_min_unicast_ms: fcc_cfg.switch_min_unicast_ms,
                    })
                }
                Ok(server) => {
                    debug!(
                        "Ignoring FCC query for multicast {} because FCC is disabled: server={}",
                        addr, server
                    );
                    None
                }
                // FCC is an optional accelerator: a malformed `fcc` parameter must
                // not fail the whole stream, just fall back to plain multicast.
                Err(e) => {
                    warn!("Ignoring invalid fcc query for {} ({}): {}", addr, value, e);
                    None
                }
            }
        }
        None => None,
    };
    let mut receiver = match state
        .shared_proxy
        .subscribe_udp(addr, effective_args.interface, fcc)
    {
        Ok(receiver) => receiver,
        Err(SharedProxySubscribeError::Busy) => {
            return HttpResponse::ServiceUnavailable().body("Too many active proxy streams");
        }
        Err(SharedProxySubscribeError::Poisoned) => {
            return HttpResponse::InternalServerError().body("Shared proxy lock poisoned");
        }
    };
    HttpResponse::Ok().streaming(stream! {
        loop {
            match receiver.recv().await {
                Ok(bytes) => yield Ok::<Bytes, anyhow::Error>(bytes),
                Err(SharedProxyRecvError::Lagged(n)) => {
                    warn!("UDP receiver lagged by {} packets", n);
                    continue;
                }
                Err(SharedProxyRecvError::Closed) => break,
            }
        }
    })
}

#[get("/udp/{addr}")]
pub(crate) async fn udp(
    state: Data<AppState>,
    addr: Path<String>,
    params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    udp_like(state, addr, params, req).await
}

#[get("/rtp/{addr}")]
pub(crate) async fn rtp(
    state: Data<AppState>,
    addr: Path<String>,
    params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    udp_like(state, addr, params, req).await
}
