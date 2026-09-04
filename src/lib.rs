use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, get,
    http::header,
    post,
    web::{Bytes, Data, Path, Query},
};
use anyhow::{Result, anyhow};
use async_stream::stream;
use chrono::Local;
use clap::Parser;
use log::{debug, warn};
use reqwest::Client;
use std::{
    collections::BTreeMap,
    collections::HashMap,
    net::SocketAddrV4,
    process::exit,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};

mod auth;
use auth::{check_auth, with_auth_cookie};

#[cfg(test)]
mod app_tests;

mod args;
use args::{Args, EffectiveArgs};

mod iptv;
use iptv::{Channel, get_channel_list_raw, get_channels, get_icon};

mod upstream_auth;
use upstream_auth::{AUTH_REFRESH_INTERVAL, UpstreamAuthManager};

mod web_assets;
use web_assets::BASE_CSS;

mod external_sources;
use external_sources::{
    FETCH_TIMEOUT as EXTRA_FETCH_TIMEOUT, fetch_playlists as fetch_extra_playlists,
    parse_xml as parse_extra_xml,
};

mod fcc;
mod proxy;
mod rtsp_client;
mod shared_proxy;

mod config;
use config::{
    CompiledConfig, Config, ManageTestResult, build_templates, compile_config, load_config,
    redacted as redacted_config, should_protect,
};

mod xmltv_output;
use fcc::{FccOptions, parse_fcc_server};
use rtsp_client::is_auth_status as is_rtsp_auth_status;
use shared_proxy::{SharedProxyRecvError, SharedProxyRegistry, SharedProxySubscribeError};
use xmltv_output::{format_time as to_xmltv_time, render as to_xmltv};

mod cache;
use cache::{
    CHANNEL_CACHE_TTL, CachedBytes, CachedChannels, CachedText, EPG_CACHE_TTL, ICON_CACHE_TTL,
    MANAGE_CACHE_TTL, MAX_ICON_CACHE_ENTRIES, MAX_UPSTREAM_CACHE_ENTRIES, PLAYLIST_CACHE_TTL,
    XMLTV_CACHE_TTL, get_text as get_cached_text, put_stale as put_stale_text,
    put_text as put_cached_text,
};

mod playlist;
use playlist::{
    ChannelEntry, EntryBuildContext, add_alias_and_resolution_for_name, apply_alias,
    finalize_entries, parse_m3u_playlist, render_playlist, resolve_group_for_alias,
};

static START_TIME: OnceLock<std::time::SystemTime> = OnceLock::new();

struct RuntimeConfig {
    config: Config,
    compiled: CompiledConfig,
    templates: handlebars::Handlebars<'static>,
    effective_args: EffectiveArgs,
}

struct AppState {
    cli_args: Args,
    config_path: Option<String>,
    extra_client: Client,
    shared_proxy: SharedProxyRegistry,
    playlist_cache: Mutex<HashMap<String, CachedText>>,
    xmltv_cache: Mutex<HashMap<String, CachedText>>,
    manage_json_cache: Mutex<HashMap<String, CachedText>>,
    manage_html_cache: Mutex<HashMap<String, CachedText>>,
    manage_raw_cache: Mutex<HashMap<String, CachedText>>,
    stale_playlists: Mutex<HashMap<String, String>>,
    stale_xmltv: Mutex<HashMap<String, String>>,
    upstream_cache: AsyncMutex<HashMap<String, CachedChannels>>,
    icon_cache: AsyncMutex<HashMap<String, CachedBytes>>,
    upstream_flights: AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    icon_flights: AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    upstream_auth: Arc<UpstreamAuthManager>,
    runtime: RwLock<RuntimeConfig>,
}

fn merge_arg(opt: Option<String>, fallback: Option<String>, default: &str) -> String {
    opt.or(fallback).unwrap_or_else(|| default.to_string())
}

fn merge_opt(opt: Option<String>, fallback: Option<String>) -> Option<String> {
    opt.or(fallback)
}

fn normalize_opt(opt: Option<String>) -> Option<String> {
    opt.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn html_escape(input: &str) -> String {
    if !input
        .bytes()
        .any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\''))
    {
        return input.to_string();
    }
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn build_effective_args(args: &Args, config: &Config) -> Result<EffectiveArgs> {
    let app = &config.app;
    let user = args.user.clone().or(app.user.clone());
    let passwd = args.passwd.clone().or(app.passwd.clone());
    let mac = args.mac.clone().or(app.mac.clone());
    if user.is_none() || passwd.is_none() || mac.is_none() {
        return Err(anyhow!(
            "Missing user/passwd/mac. Provide via CLI or config [app]."
        ));
    }
    Ok(EffectiveArgs {
        user: user.unwrap(),
        passwd: passwd.unwrap(),
        mac: mac.unwrap(),
        imei: merge_arg(args.imei.clone(), app.imei.clone(), ""),
        bind: merge_arg(args.bind.clone(), app.bind.clone(), "0.0.0.0:7878"),
        address: merge_arg(args.address.clone(), app.address.clone(), ""),
        interface: normalize_opt(merge_opt(args.interface.clone(), app.interface.clone())),
        extra_playlist: args.extra_playlist.clone(),
        extra_xmltv: args.extra_xmltv.clone(),
        udp_proxy: args.udp_proxy || app.udp_proxy,
        rtsp_proxy: args.rtsp_proxy || app.rtsp_proxy,
        fcc_enabled: config.fcc.enabled,
        fcc_max_redirects: config.fcc.max_redirects,
        fcc_switch_extra_packets: config.fcc.switch_extra_packets,
        fcc_switch_min_unicast_ms: config.fcc.switch_min_unicast_ms,
    })
}

fn output_effective_args(state: &AppState) -> Result<EffectiveArgs> {
    let runtime = state
        .runtime
        .read()
        .map_err(|_| anyhow!("Config lock poisoned"))?;
    Ok(runtime.effective_args.clone())
}

fn upstream_cache_key(args: &EffectiveArgs, need_epg: bool, scheme: &str, host: &str) -> String {
    let identity = format!(
        "{}\0{}\0{}\0{}\0{}\0{:?}\0{}\0{}\0{}\0{}\0{}",
        args.user,
        args.passwd,
        args.mac,
        args.imei,
        args.address,
        args.interface,
        args.udp_proxy,
        args.rtsp_proxy,
        args.fcc_enabled,
        scheme,
        host
    );
    format!("{:x}|epg={need_epg}", md5::compute(identity.as_bytes()))
}

async fn get_channels_cached(
    state: &AppState,
    args: &EffectiveArgs,
    need_epg: bool,
    scheme: &str,
    host: &str,
) -> Result<Vec<Channel>> {
    let key = upstream_cache_key(args, need_epg, scheme, host);
    {
        let mut cache = state.upstream_cache.lock().await;
        let now = std::time::Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        if let Some(cached) = cache.get(&key) {
            return Ok(cached.channels.clone());
        }
    }

    let flight = {
        let mut flights = state.upstream_flights.lock().await;
        flights
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    let _flight_guard = flight.lock().await;
    if let Some(channels) = state
        .upstream_cache
        .lock()
        .await
        .get(&key)
        .filter(|cached| cached.expires_at > std::time::Instant::now())
        .map(|cached| cached.channels.clone())
    {
        return Ok(channels);
    }

    let channels = match get_channels(args, need_epg, scheme, host).await {
        Ok(channels) => {
            state.upstream_auth.mark_success();
            channels
        }
        Err(error) => {
            state.upstream_flights.lock().await.remove(&key);
            return Err(error);
        }
    };
    let mut cache = state.upstream_cache.lock().await;
    if cache.len() >= MAX_UPSTREAM_CACHE_ENTRIES
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(key, _)| key.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(
        key.clone(),
        CachedChannels {
            expires_at: std::time::Instant::now()
                + if need_epg {
                    EPG_CACHE_TTL
                } else {
                    CHANNEL_CACHE_TTL
                },
            channels: channels.clone(),
        },
    );
    drop(cache);
    state.upstream_flights.lock().await.remove(&key);
    Ok(channels)
}

async fn get_icon_cached(state: &AppState, args: &EffectiveArgs, id: &str) -> Result<Vec<u8>> {
    let key = format!(
        "{:x}|{}",
        md5::compute(
            format!(
                "{}\0{}\0{}\0{:?}",
                args.user, args.passwd, args.mac, args.interface
            )
            .as_bytes()
        ),
        id
    );
    {
        let mut cache = state.icon_cache.lock().await;
        let now = std::time::Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        if let Some(cached) = cache.get(&key) {
            return Ok(cached.body.clone());
        }
    }

    let flight = {
        let mut flights = state.icon_flights.lock().await;
        flights
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    let _flight_guard = flight.lock().await;
    if let Some(body) = state
        .icon_cache
        .lock()
        .await
        .get(&key)
        .filter(|cached| cached.expires_at > std::time::Instant::now())
        .map(|cached| cached.body.clone())
    {
        return Ok(body);
    }

    let icon = match get_icon(args, id).await {
        Ok(icon) => icon,
        Err(error) => {
            state.icon_flights.lock().await.remove(&key);
            return Err(error);
        }
    };
    let mut cache = state.icon_cache.lock().await;
    if cache.len() >= MAX_ICON_CACHE_ENTRIES
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(key, _)| key.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(
        key.clone(),
        CachedBytes {
            expires_at: std::time::Instant::now() + ICON_CACHE_TTL,
            body: icon.clone(),
        },
    );
    drop(cache);
    state.icon_flights.lock().await.remove(&key);
    Ok(icon)
}

fn build_local_entries(
    channels: Vec<Channel>,
    args: &EffectiveArgs,
    scheme: &str,
    host: &str,
    playseek: &str,
    start_index: usize,
    limit: Option<usize>,
) -> Vec<ChannelEntry> {
    let capacity = limit.unwrap_or(channels.len()).min(channels.len());
    let mut entries = Vec::with_capacity(capacity);
    for (index, c) in (start_index..).zip(channels.into_iter().take(limit.unwrap_or(usize::MAX))) {
        let url = if args.udp_proxy {
            c.igmp.clone().unwrap_or_else(|| c.rtsp.clone())
        } else {
            c.rtsp.clone()
        };
        let (catchup, catchup_source, catchup_attr) = if let Some(url) = c.time_shift_url.as_ref() {
            let source = format!("{}&playseek={}", url, playseek);
            let attr = format!(
                r#" catchup="default" catchup-source="{}&playseek={}" "#,
                url, playseek
            );
            ("default".to_string(), source, attr)
        } else {
            (String::new(), String::new(), String::new())
        };
        let entry = ChannelEntry {
            key: format!("gd:{}:{}", c.id, index),
            source: String::from("gd-iptv"),
            channel_id: Some(c.id),
            url,
            raw_name: c.name.clone(),
            alias_name: String::new(),
            group: String::new(),
            tvg_id: c.id.to_string(),
            tvg_name: c.name.clone(),
            tvg_logo: format!("{scheme}://{host}/logo/{}.png", c.id),
            tvg_chno: c.id.to_string(),
            catchup,
            catchup_source,
            catchup_attr,
            extras: BTreeMap::new(),
            resolution_score: 0,
            resolution_label: "Unknown".to_string(),
            original_index: index,
        };
        entries.push(entry);
    }
    entries
}

fn append_auth_token(url: &str, token: &str) -> String {
    if token.is_empty() {
        return url.to_string();
    }
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.query_pairs().any(|(key, _)| key == "token") {
        return url.to_string();
    }
    parsed.query_pairs_mut().append_pair("token", token);
    parsed.to_string()
}

fn protect_local_entry_urls(entries: &mut [ChannelEntry], config: &Config) {
    for entry in entries.iter_mut().filter(|entry| entry.source == "gd-iptv") {
        let endpoint = reqwest::Url::parse(&entry.url).ok().and_then(|url| {
            let path = url.path();
            if path.starts_with("/rtsp/") {
                Some("rtsp")
            } else if path.starts_with("/udp/") || path.starts_with("/rtp/") {
                Some("udp")
            } else {
                None
            }
        });
        if endpoint.is_some_and(|endpoint| should_protect(config, endpoint)) {
            entry.url = append_auth_token(&entry.url, &config.auth.token);
        }
        if should_protect(config, "logo") {
            entry.tvg_logo = append_auth_token(&entry.tvg_logo, &config.auth.token);
        }
        if !entry.catchup_source.is_empty() && should_protect(config, "rtsp") {
            let (base, playseek) = entry
                .catchup_source
                .split_once("&playseek=")
                .map(|(base, value)| (base, Some(value.to_string())))
                .unwrap_or((&entry.catchup_source, None));
            let protected = append_auth_token(base, &config.auth.token);
            entry.catchup_source = match playseek {
                Some(playseek) => format!("{protected}&playseek={playseek}"),
                None => protected,
            };
            entry.catchup_attr = format!(
                r#" catchup="default" catchup-source="{}" "#,
                entry.catchup_source
            );
        }
    }
}

mod handlers;
use handlers::{
    logo, manage_channels, manage_channels_html, manage_channels_raw, manage_config, manage_index,
    manage_reload, manage_test, playlist_handler, rtp, rtsp, status, udp, xmltv,
};

pub async fn run() -> std::io::Result<()> {
    env_logger::init();
    let _ = START_TIME.set(std::time::SystemTime::now());
    let args = Args::parse();

    let config = match load_config(args.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            exit(1);
        }
    };
    let compiled = match compile_config(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to compile config: {}", e);
            exit(1);
        }
    };
    let templates = match build_templates(&config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to build templates: {}", e);
            exit(1);
        }
    };
    let effective_args = match build_effective_args(&args, &config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };
    debug!(
        "Effective runtime config bind={} interface={:?} udp_proxy={} rtsp_proxy={} fcc_enabled={} fcc_max_redirects={} fcc_switch_extra_packets={} fcc_switch_min_unicast_ms={}",
        effective_args.bind,
        effective_args.interface,
        effective_args.udp_proxy,
        effective_args.rtsp_proxy,
        effective_args.fcc_enabled,
        effective_args.fcc_max_redirects,
        effective_args.fcc_switch_extra_packets,
        effective_args.fcc_switch_min_unicast_ms
    );

    let upstream_auth = Arc::new(UpstreamAuthManager::default());
    let state = Data::new(AppState {
        cli_args: args.clone(),
        config_path: args.config.clone(),
        extra_client: Client::builder()
            .timeout(EXTRA_FETCH_TIMEOUT)
            .build()
            .unwrap_or_else(|e| {
                eprintln!("Failed to build extra fetch client: {}", e);
                exit(1);
            }),
        shared_proxy: SharedProxyRegistry::new(),
        playlist_cache: Mutex::new(HashMap::new()),
        xmltv_cache: Mutex::new(HashMap::new()),
        manage_json_cache: Mutex::new(HashMap::new()),
        manage_html_cache: Mutex::new(HashMap::new()),
        manage_raw_cache: Mutex::new(HashMap::new()),
        stale_playlists: Mutex::new(HashMap::new()),
        stale_xmltv: Mutex::new(HashMap::new()),
        upstream_cache: AsyncMutex::new(HashMap::new()),
        icon_cache: AsyncMutex::new(HashMap::new()),
        upstream_flights: AsyncMutex::new(HashMap::new()),
        icon_flights: AsyncMutex::new(HashMap::new()),
        upstream_auth: upstream_auth.clone(),
        runtime: RwLock::new(RuntimeConfig {
            config,
            compiled,
            templates,
            effective_args: effective_args.clone(),
        }),
    });

    let periodic_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUTH_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first interval tick is immediate. Normal startup traffic performs
        // the initial login, so wait for the first real six-hour deadline.
        interval.tick().await;
        loop {
            interval.tick().await;
            let args = match output_effective_args(&periodic_state) {
                Ok(args) => args,
                Err(error) => {
                    warn!("Periodic authorization refresh skipped: {error}");
                    continue;
                }
            };
            let retry_delays = [
                Duration::ZERO,
                Duration::from_secs(60),
                Duration::from_secs(5 * 60),
            ];
            for (attempt, delay) in retry_delays.into_iter().enumerate() {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                match periodic_state.upstream_auth.force_refresh(&args).await {
                    Ok(()) => break,
                    Err(error) => warn!(
                        "Periodic upstream authorization refresh attempt {}/{} failed: {error}",
                        attempt + 1,
                        retry_delays.len()
                    ),
                }
            }
        }
    });

    let bind_addr = effective_args.bind.clone();
    HttpServer::new(move || {
        App::new()
            .service(xmltv)
            .service(playlist_handler)
            .service(logo)
            .service(rtsp)
            .service(udp)
            .service(rtp)
            .service(status)
            .service(manage_index)
            .service(manage_config)
            .service(manage_reload)
            .service(manage_test)
            .service(manage_channels)
            .service(manage_channels_raw)
            .service(manage_channels_html)
            .app_data(state.clone())
    })
    .bind(bind_addr)?
    .run()
    .await
}
