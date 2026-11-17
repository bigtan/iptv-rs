use actix_web::{App, HttpServer, web::Data};
use anyhow::{Result, anyhow};
use clap::Parser;
use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    process::exit,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

mod auth;
use auth::{check_auth, with_auth_cookie};

#[cfg(test)]
mod app_tests;

mod args;
use args::{Args, EffectiveArgs, UpstreamCredentials};

mod iptv;
use iptv::{Channel, get_channel_list_raw, get_channels, get_icon};

mod upstream_auth;
use upstream_auth::{AUTH_REFRESH_INTERVAL, UpstreamAuthManager};

mod web_assets;
use web_assets::BASE_CSS;

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
use shared_proxy::SharedProxyRegistry;

mod cache;
use cache::{CHANNEL_CACHE_TTL, CacheStore, EPG_CACHE_TTL};

mod playlist;
use playlist::{ChannelEntry, apply_alias};

pub(crate) static START_TIME: OnceLock<std::time::SystemTime> = OnceLock::new();

pub(crate) struct RuntimeConfig {
    pub(crate) config: Config,
    pub(crate) compiled: CompiledConfig,
    pub(crate) templates: handlebars::Handlebars<'static>,
    pub(crate) effective_args: EffectiveArgs,
}

pub(crate) struct AppState {
    pub(crate) cli_args: Args,
    pub(crate) config_path: Option<String>,
    pub(crate) shared_proxy: SharedProxyRegistry,
    pub(crate) caches: CacheStore,
    pub(crate) upstream_auth: Arc<UpstreamAuthManager>,
    pub(crate) runtime: RwLock<Arc<RuntimeConfig>>,
}

impl AppState {
    pub(crate) fn runtime(&self) -> Arc<RuntimeConfig> {
        self.runtime
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
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

pub(crate) fn html_escape(input: &str) -> String {
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

pub(crate) fn build_effective_args(args: &Args, config: &Config) -> Result<EffectiveArgs> {
    let app = &config.app;
    let udp_proxy = args.udp_proxy || app.udp_proxy;
    let rtsp_proxy = args.rtsp_proxy || app.rtsp_proxy;

    let workers = args.workers.or(app.workers);
    if matches!(workers, Some(0)) {
        return Err(anyhow!("workers must be at least 1"));
    }

    let user = normalize_opt(merge_opt(args.user.clone(), app.user.clone()));
    let passwd = normalize_opt(merge_opt(args.passwd.clone(), app.passwd.clone()));
    let mac = normalize_opt(merge_opt(args.mac.clone(), app.mac.clone()));

    let upstream = match (user, passwd, mac) {
        (Some(user), Some(passwd), Some(mac)) => Some(UpstreamCredentials {
            user,
            passwd,
            mac,
            imei: merge_arg(args.imei.clone(), app.imei.clone(), ""),
            address: merge_arg(args.address.clone(), app.address.clone(), ""),
        }),
        (None, None, None) if udp_proxy || rtsp_proxy => None,
        (None, None, None) => {
            return Err(anyhow!(
                "Missing user/passwd/mac and neither udp_proxy nor rtsp_proxy is enabled. \
                 Provide upstream credentials via CLI or config [app], or enable udp_proxy/rtsp_proxy."
            ));
        }
        _ => {
            return Err(anyhow!(
                "Incomplete upstream credentials: user, passwd, and mac must all be provided together, \
                 or all omitted for standalone proxy-only mode."
            ));
        }
    };

    let bind = normalize_opt(merge_opt(args.bind.clone(), app.bind.clone()))
        .unwrap_or_else(|| "0.0.0.0:7878".to_string());
    let bind_interface = normalize_opt(merge_opt(
        args.bind_interface.clone(),
        app.bind_interface.clone(),
    ));
    let interface = normalize_opt(merge_opt(args.interface.clone(), app.interface.clone()));

    Ok(EffectiveArgs {
        upstream,
        bind,
        bind_interface,
        workers,
        interface,
        udp_proxy,
        rtsp_proxy,
        fcc_enabled: config.fcc.enabled,
        fcc_max_redirects: config.fcc.max_redirects,
        fcc_switch_extra_packets: config.fcc.switch_extra_packets,
        fcc_switch_min_unicast_ms: config.fcc.switch_min_unicast_ms,
    })
}

pub(crate) fn upstream_cache_key(
    creds: &UpstreamCredentials,
    interface: Option<&str>,
    need_epg: bool,
) -> String {
    let identity = format!(
        "{}\0{}\0{}\0{}\0{}\0{:?}",
        creds.user, creds.passwd, creds.mac, creds.imei, creds.address, interface,
    );
    format!("{:x}|epg={need_epg}", md5::compute(identity.as_bytes()))
}

pub(crate) async fn get_channels_cached(
    state: &AppState,
    args: &EffectiveArgs,
    need_epg: bool,
) -> Result<Vec<Channel>> {
    let Some(creds) = args.upstream.as_ref() else {
        return Ok(Vec::new());
    };
    let key = upstream_cache_key(creds, args.interface.as_deref(), need_epg);
    let ttl = if need_epg {
        EPG_CACHE_TTL
    } else {
        CHANNEL_CACHE_TTL
    };
    state
        .caches
        .get_or_try_init_channels(key, ttl, || {
            get_channels(
                &state.upstream_auth,
                creds,
                args.interface.as_deref(),
                need_epg,
            )
        })
        .await
}

pub(crate) async fn get_icon_cached(
    state: &AppState,
    creds: &UpstreamCredentials,
    interface: Option<&str>,
    id: &str,
) -> Result<Vec<u8>> {
    let key = format!(
        "{:x}|{}",
        md5::compute(
            format!(
                "{}\0{}\0{}\0{:?}",
                creds.user, creds.passwd, creds.mac, interface
            )
            .as_bytes()
        ),
        id
    );
    state
        .caches
        .get_or_try_init_icon(key, || get_icon(&state.upstream_auth, creds, interface, id))
        .await
}

fn rewrite_rtsp_url(raw: &str, rtsp_proxy: bool, scheme: &str, host: &str) -> String {
    if rtsp_proxy && let Some(rest) = raw.strip_prefix("rtsp://") {
        return format!("{scheme}://{host}/rtsp/{rest}");
    }
    raw.to_string()
}

pub(crate) fn build_local_entries(
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
        let rtsp_url = rewrite_rtsp_url(&c.rtsp, args.rtsp_proxy, scheme, host);
        let url = if args.udp_proxy {
            if let Some(raw_igmp) = c.igmp.as_deref() {
                let mut proxied = if let Some(rest) = raw_igmp.strip_prefix("igmp://") {
                    format!("{scheme}://{host}/udp/{rest}")
                } else {
                    raw_igmp.to_string()
                };
                if args.fcc_enabled
                    && let Some(fcc) = c.fcc_server.as_deref()
                {
                    let sep = if proxied.contains('?') { '&' } else { '?' };
                    proxied.push(sep);
                    proxied.push_str("fcc=");
                    proxied.push_str(fcc);
                }
                proxied
            } else {
                rtsp_url
            }
        } else {
            rtsp_url
        };

        let (catchup, catchup_source, catchup_attr) =
            if let Some(raw_ts) = c.time_shift_url.as_ref() {
                let ts_url = rewrite_rtsp_url(raw_ts, args.rtsp_proxy, scheme, host);
                let source = format!("{ts_url}&playseek={playseek}");
                let attr = format!(r#" catchup="default" catchup-source="{source}" "#);
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

pub(crate) fn protect_local_entry_urls(entries: &mut [ChannelEntry], config: &Config) {
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

#[derive(Debug)]
pub(crate) enum ReloadError {
    NoConfigPath,
    LoadOrCompile(anyhow::Error),
    InvalidArgs(anyhow::Error),
    ListenerChanged(String),
}

impl fmt::Display for ReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloadError::NoConfigPath => write!(f, "No config path specified"),
            ReloadError::LoadOrCompile(e) => write!(f, "{e}"),
            ReloadError::InvalidArgs(e) => write!(f, "{e}"),
            ReloadError::ListenerChanged(msg) => write!(f, "{msg}"),
        }
    }
}

pub(crate) fn reload_runtime_config(
    state: &AppState,
) -> std::result::Result<Arc<RuntimeConfig>, ReloadError> {
    let Some(path) = state.config_path.as_deref() else {
        return Err(ReloadError::NoConfigPath);
    };
    let config = load_config(Some(path)).map_err(ReloadError::LoadOrCompile)?;
    let compiled = compile_config(&config).map_err(ReloadError::LoadOrCompile)?;
    let templates = build_templates(&config).map_err(ReloadError::LoadOrCompile)?;
    let effective_args =
        build_effective_args(&state.cli_args, &config).map_err(ReloadError::InvalidArgs)?;

    let current = state.runtime();
    if effective_args.bind != current.effective_args.bind
        || effective_args.bind_interface != current.effective_args.bind_interface
        || effective_args.workers != current.effective_args.workers
    {
        return Err(ReloadError::ListenerChanged(
            "HTTP listener settings (bind, bind_interface, or workers) changed; \
             restart the service to apply this configuration"
                .to_string(),
        ));
    }

    state
        .upstream_auth
        .on_config_change(&current.effective_args, &effective_args);

    let next_runtime = Arc::new(RuntimeConfig {
        config,
        compiled,
        templates,
        effective_args,
    });
    *state.runtime.write().unwrap_or_else(|e| e.into_inner()) = next_runtime.clone();
    state.caches.clear_all();
    info!("Reloaded configuration from {path}");
    Ok(next_runtime)
}

fn bind_socket_addr(
    addr: SocketAddr,
    bind_interface: Option<&str>,
) -> std::io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        let _ = socket.set_only_v6(false);
    }
    socket.set_reuse_address(true)?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(iface) = bind_interface {
        socket.bind_device(Some(iface.as_bytes()))?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if let Some(iface) = bind_interface {
        warn!(
            "bind_interface ({iface}) requires SO_BINDTODEVICE on Linux/Android/Fuchsia; \
             binding {addr} without device restriction"
        );
    }

    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

pub(crate) fn bind_http_listener(
    bind: &str,
    bind_interface: Option<&str>,
) -> std::io::Result<TcpListener> {
    let addrs: Vec<SocketAddr> = bind.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unable to resolve bind address `{bind}`"),
        ));
    }
    let mut last_err = None;
    for addr in addrs {
        match bind_socket_addr(addr, bind_interface) {
            Ok(listener) => return Ok(listener),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap())
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
        "Effective runtime config bind={} bind_interface={:?} workers={:?} interface={:?} \
         proxy_only={} udp_proxy={} rtsp_proxy={} fcc_enabled={} fcc_max_redirects={} \
         fcc_switch_extra_packets={} fcc_switch_min_unicast_ms={}",
        effective_args.bind,
        effective_args.bind_interface,
        effective_args.workers,
        effective_args.interface,
        effective_args.upstream.is_none(),
        effective_args.udp_proxy,
        effective_args.rtsp_proxy,
        effective_args.fcc_enabled,
        effective_args.fcc_max_redirects,
        effective_args.fcc_switch_extra_packets,
        effective_args.fcc_switch_min_unicast_ms
    );

    let listener = bind_http_listener(
        &effective_args.bind,
        effective_args.bind_interface.as_deref(),
    )?;
    let workers = effective_args.workers;

    let upstream_auth = Arc::new(UpstreamAuthManager::default());
    let state = Data::new(AppState {
        cli_args: args.clone(),
        config_path: args.config.clone(),
        shared_proxy: SharedProxyRegistry::new(),
        caches: CacheStore::new(),
        upstream_auth,
        runtime: RwLock::new(Arc::new(RuntimeConfig {
            config,
            compiled,
            templates,
            effective_args,
        })),
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
            let args = periodic_state.runtime().effective_args.clone();
            if args.upstream.is_none() {
                debug!("Periodic upstream authorization refresh skipped in proxy-only mode");
                continue;
            }
            let retry_delays = [
                Duration::ZERO,
                Duration::from_secs(60),
                Duration::from_secs(5 * 60),
            ];
            let mut last_error = None;
            for (attempt, delay) in retry_delays.into_iter().enumerate() {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                match periodic_state.upstream_auth.force_refresh(&args).await {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        warn!(
                            "Periodic upstream authorization refresh attempt {}/{} failed: {error}",
                            attempt + 1,
                            retry_delays.len()
                        );
                        last_error = Some(error);
                    }
                }
            }
            if let Some(error) = last_error {
                error!(
                    "Periodic upstream authorization refresh exhausted all {} attempts; \
                     the next scheduled refresh is in {:?}: {error}",
                    retry_delays.len(),
                    AUTH_REFRESH_INTERVAL
                );
            }
        }
    });

    #[cfg(unix)]
    {
        let sighup_state = state.clone();
        tokio::spawn(async move {
            let mut sig =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(sig) => sig,
                    Err(error) => {
                        warn!("Failed to install SIGHUP reload handler: {error}");
                        return;
                    }
                };
            while sig.recv().await.is_some() {
                if let Err(error) = reload_runtime_config(&sighup_state) {
                    warn!("SIGHUP reload warning: {error}");
                }
            }
        });
    }

    let mut server = HttpServer::new(move || {
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
    });
    if let Some(workers) = workers {
        server = server.workers(workers);
    }
    server.listen(listener)?.run().await
}
