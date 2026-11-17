use crate::{
    AppState, apply_alias,
    auth::check_auth,
    build_local_entries,
    fcc::{FccOptions, parse_fcc_server},
    get_channels_cached, get_icon_cached,
    playlist::{EntryBuildContext, finalize_entries, render_playlist},
    protect_local_entry_urls, proxy,
    rtsp_client::is_auth_status as is_rtsp_auth_status,
    shared_proxy::{SharedProxyRecvError, SharedProxySubscribeError},
    xmltv_output::{format_time as to_xmltv_time, render as to_xmltv},
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    http::header,
    web::{Bytes, Data, Path, Query},
};
use async_stream::stream;
use chrono::Local;
use log::{debug, warn};
use std::{collections::BTreeMap, net::SocketAddrV4, str::FromStr};

pub(crate) fn is_valid_logo_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[get("/xmltv")]
pub(crate) async fn xmltv(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get EPG");
    let runtime = state.runtime();
    if !check_auth(&req, &runtime.config, "xmltv") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    if runtime.effective_args.upstream.is_none() {
        let empty = to_xmltv(&[]).unwrap_or_else(|_| {
            r#"<?xml version="1.0" encoding="UTF-8"?><tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy"/>"#
                .to_string()
        });
        return HttpResponse::Ok().content_type("text/xml").body(empty);
    }

    let use_alias_name = runtime.config.xmltv.use_alias_name;
    let cache_key = format!("alias={use_alias_name}");
    if let Some(xml) = state.caches.get_xmltv(&cache_key) {
        return HttpResponse::Ok().content_type("text/xml").body(xml);
    }

    let expected_gen = state.caches.generation();
    let xml = get_channels_cached(&state, &runtime.effective_args, true)
        .await
        .and_then(|mut ch| {
            let live = state.runtime();
            if live.config.xmltv.use_alias_name {
                for channel in ch.iter_mut() {
                    let alias = apply_alias(&channel.name, &live.config, &live.compiled);
                    let alias = alias.trim().to_string();
                    if !alias.is_empty() {
                        channel.name = alias;
                    }
                }
            }
            to_xmltv(&ch)
        });

    match xml {
        Err(e) => {
            if let Some(old_xmltv) = state.caches.get_stale_xmltv(&cache_key) {
                HttpResponse::Ok().content_type("text/xml").body(old_xmltv)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(xml) => {
            state.caches.put_xmltv(expected_gen, cache_key, xml.clone());
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
    let runtime = state.runtime();
    if !check_auth(&req, &runtime.config, "logo") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let id = path.into_inner();
    if !is_valid_logo_id(&id) {
        return HttpResponse::BadRequest().body("Invalid logo id");
    }
    let Some(creds) = runtime.effective_args.upstream.as_ref() else {
        return HttpResponse::NotFound()
            .body("Channel logos are unavailable in proxy-only mode (no upstream credentials)");
    };
    match get_icon_cached(
        &state,
        creds,
        runtime.effective_args.interface.as_deref(),
        &id,
    )
    .await
    {
        Ok(icon) => HttpResponse::Ok().content_type("image/png").body(icon),
        Err(e) => HttpResponse::NotFound().body(format!("Error getting channel logo: {}", e)),
    }
}

#[get("/playlist")]
pub(crate) async fn playlist_handler(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get playlist");
    let runtime = state.runtime();
    if !check_auth(&req, &runtime.config, "playlist") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    if runtime.effective_args.upstream.is_none() {
        return HttpResponse::Ok()
            .content_type("application/vnd.apple.mpegurl")
            .body("#EXTM3U\n");
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
        "{scheme}|{host}|{is_kodi}|{}|{}|{}",
        output_args.udp_proxy, output_args.rtsp_proxy, output_args.fcc_enabled
    );
    if let Some(playlist) = state.caches.get_playlist(&cache_key) {
        return HttpResponse::Ok()
            .content_type("application/vnd.apple.mpegurl")
            .body(playlist);
    }

    let expected_gen = state.caches.generation();
    match get_channels_cached(&state, output_args, false).await {
        Err(e) => {
            if let Some(old_playlist) = state.caches.get_stale_playlist(&cache_key) {
                HttpResponse::Ok()
                    .content_type("application/vnd.apple.mpegurl")
                    .body(old_playlist)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(ch) => {
            let live = state.runtime();
            let mut entries =
                build_local_entries(ch, &live.effective_args, &scheme, &host, playseek, 0, None);
            let ctx = EntryBuildContext {
                config: &live.config,
                compiled: &live.compiled,
            };
            protect_local_entry_urls(&mut entries, &live.config);
            let entries = finalize_entries(entries, &ctx);
            let playlist = match render_playlist(&entries, &live.templates) {
                Ok(playlist) => playlist,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Template render error: {}", e));
                }
            };
            state
                .caches
                .put_playlist(expected_gen, cache_key, playlist.clone());
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
    let runtime = state.runtime();
    if !runtime.effective_args.rtsp_proxy {
        return HttpResponse::NotFound().body("RTSP proxy disabled");
    }
    if !check_auth(&req, &runtime.config, "rtsp") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let effective_args = runtime.effective_args.clone();

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
    if effective_args.upstream.is_some()
        && let Err(error) = state.upstream_auth.ensure_fresh(&effective_args).await
    {
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
        Err(error) if is_rtsp_auth_status(&error) && effective_args.upstream.is_some() => {
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
    let runtime = state.runtime();
    if !runtime.effective_args.udp_proxy {
        return HttpResponse::NotFound().body("UDP proxy disabled");
    }
    if !check_auth(&req, &runtime.config, "udp") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let effective_args = runtime.effective_args.clone();

    let addr = match SocketAddrV4::from_str(&addr) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Error: {}", e)),
    };
    if effective_args.upstream.is_some()
        && let Err(error) = state.upstream_auth.ensure_fresh(&effective_args).await
    {
        warn!("Pre-stream upstream authorization refresh failed: {error}");
    }
    let fcc = match params.get("fcc") {
        Some(value) => {
            // Read FCC tuning from the live config when a new shared UDP source
            // is created.
            let fcc_cfg = state.runtime().config.fcc.clone();
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
                    debug!("UDP receiver lagged by {} packets", n);
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
