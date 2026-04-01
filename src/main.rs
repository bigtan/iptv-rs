use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder,
    cookie::{Cookie, SameSite},
    get,
    http::header,
    post,
    web::{Bytes, Data, Path, Query},
};
use anyhow::{Result, anyhow};
use async_stream::stream;
use chrono::{FixedOffset, Local, TimeZone, Utc};
use clap::Parser;
use futures_core::Stream;
use futures_util::StreamExt;
use log::{debug, warn};
use reqwest::Client;
use std::{
    collections::BTreeMap,
    collections::HashMap,
    collections::VecDeque,
    io::{BufWriter, Cursor},
    net::SocketAddrV4,
    process::exit,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};
use xml::{
    EventReader,
    reader::XmlEvent as XmlReadEvent,
    writer::{EmitterConfig, XmlEvent as XmlWriteEvent},
};

use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};

const AUTH_COOKIE_NAME: &str = "iptv_token";

fn extract_explicit_token(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }
    if let Some(token) = req
        .headers()
        .get("X-Api-Token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_string());
    }
    if let Some(query) = req.uri().query() {
        for part in query.split('&') {
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            if key == "token" {
                let value = kv.next().unwrap_or("");
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_token(req: &HttpRequest) -> Option<String> {
    if let Some(token) = extract_explicit_token(req) {
        return Some(token);
    }
    req.cookie(AUTH_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string())
}

fn maybe_auth_cookie(
    req: &HttpRequest,
    config: &Config,
    endpoint: &str,
) -> Option<Cookie<'static>> {
    if !should_protect(config, endpoint) || config.auth.token.is_empty() {
        return None;
    }
    let explicit = extract_explicit_token(req)?;
    if explicit != config.auth.token {
        return None;
    }
    if req
        .cookie(AUTH_COOKIE_NAME)
        .is_some_and(|cookie| cookie.value() == explicit)
    {
        return None;
    }
    Some(
        Cookie::build(AUTH_COOKIE_NAME, explicit)
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .finish(),
    )
}

fn with_auth_cookie(
    req: &HttpRequest,
    config: &Config,
    endpoint: &str,
    mut response: HttpResponse,
) -> HttpResponse {
    if let Some(cookie) = maybe_auth_cookie(req, config, endpoint) {
        if let Ok(value) = header::HeaderValue::from_str(&cookie.to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn check_auth(req: &HttpRequest, config: &Config, endpoint: &str) -> bool {
    if !should_protect(config, endpoint) {
        return true;
    }
    if config.auth.token.is_empty() {
        return true;
    }
    let token = extract_token(req).unwrap_or_default();
    token == config.auth.token
}

mod args;
use args::{Args, EffectiveArgs};

mod iptv;
use iptv::{Channel, get_channel_list_raw, get_channels, get_icon};

mod proxy;
mod rtsp_client;

mod config;
use config::{
    CompiledConfig, Config, ManageTestResult, build_templates, compile_config, load_config,
    should_protect,
};

mod playlist;
use playlist::{
    ChannelEntry, EntryBuildContext, add_alias_and_resolution_for_name, apply_alias,
    finalize_entries, parse_m3u_playlist, render_playlist, resolve_group_for_alias,
};

static OLD_PLAYLIST: Mutex<Option<String>> = Mutex::new(None);
static OLD_XMLTV: Mutex<Option<String>> = Mutex::new(None);
static START_TIME: OnceLock<std::time::SystemTime> = OnceLock::new();

struct RuntimeConfig {
    config: Config,
    compiled: CompiledConfig,
    templates: handlebars::Handlebars<'static>,
}

struct AppState {
    args: EffectiveArgs,
    config_path: Option<String>,
    extra_client: Client,
    proxy_slots: Arc<Semaphore>,
    shared_proxies: Mutex<HashMap<String, Arc<SharedProxyHub>>>,
    playlist_cache: Mutex<HashMap<String, CachedText>>,
    xmltv_cache: Mutex<HashMap<String, CachedText>>,
    manage_json_cache: Mutex<HashMap<String, CachedText>>,
    manage_html_cache: Mutex<HashMap<String, CachedText>>,
    manage_raw_cache: Mutex<HashMap<String, CachedText>>,
    runtime: RwLock<RuntimeConfig>,
}

struct CachedText {
    expires_at: std::time::Instant,
    body: String,
}

struct SharedProxyHub {
    inner: Mutex<SharedProxyInner>,
    notify: Notify,
}

struct SharedProxyInner {
    chunks: VecDeque<(u64, Bytes)>,
    next_seq: u64,
    receivers: usize,
    closed: bool,
}

struct SharedProxyReceiver {
    hub: Arc<SharedProxyHub>,
    next_seq: u64,
}

enum SharedProxyRecvError {
    Lagged(u64),
    Closed,
}

const EXTRA_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const EXTRA_FETCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROXY_STREAMS: usize = 64;
const SHARED_PROXY_BATCH_BYTES: usize = 16 * 1024;
const SHARED_PROXY_BUFFER: usize = 512;
const SHARED_PROXY_BATCH_FLUSH: Duration = Duration::from_millis(2);
const OUTPUT_CACHE_TTL: Duration = Duration::from_secs(5);

fn shared_udp_key(addr: &SocketAddrV4, if_name: Option<&str>) -> String {
    format!("udp|{}|{}", if_name.unwrap_or(""), addr)
}

fn get_cached_text(cache: &Mutex<HashMap<String, CachedText>>, key: &str) -> Option<String> {
    let mut cache = cache.lock().ok()?;
    let cached = cache.get(key)?;
    if cached.expires_at <= std::time::Instant::now() {
        cache.remove(key);
        return None;
    }
    Some(cached.body.clone())
}

fn put_cached_text(cache: &Mutex<HashMap<String, CachedText>>, key: String, body: String) {
    if let Ok(mut cache) = cache.lock() {
        cache.insert(
            key,
            CachedText {
                expires_at: std::time::Instant::now() + OUTPUT_CACHE_TTL,
                body,
            },
        );
    }
}

fn spawn_shared_proxy_task<S>(
    state: Data<AppState>,
    key: String,
    hub: Arc<SharedProxyHub>,
    stream: S,
) where
    S: Stream<Item = Result<Bytes>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut stream = Box::pin(stream);
        let mut pending = Vec::with_capacity(SHARED_PROXY_BATCH_BYTES);
        loop {
            if hub.receiver_count() == 0 {
                break;
            }

            match tokio::time::timeout(SHARED_PROXY_BATCH_FLUSH, stream.next()).await {
                Ok(Some(Ok(bytes))) => {
                    pending.extend_from_slice(bytes.as_ref());
                    if pending.len() >= SHARED_PROXY_BATCH_BYTES {
                        hub.push(Bytes::from(std::mem::take(&mut pending)));
                        pending = Vec::with_capacity(SHARED_PROXY_BATCH_BYTES);
                    }
                }
                Ok(Some(Err(e))) => {
                    if !pending.is_empty() {
                        hub.push(Bytes::from(std::mem::take(&mut pending)));
                    }
                    warn!("Shared proxy stream {} ended with error: {}", key, e);
                    break;
                }
                Ok(None) => {
                    if !pending.is_empty() {
                        hub.push(Bytes::from(std::mem::take(&mut pending)));
                    }
                    break;
                }
                Err(_) => {
                    if !pending.is_empty() {
                        hub.push(Bytes::from(std::mem::take(&mut pending)));
                        pending = Vec::with_capacity(SHARED_PROXY_BATCH_BYTES);
                    }
                }
            }
        }
        hub.close();
        if let Ok(mut shared) = state.shared_proxies.lock() {
            shared.remove(&key);
        }
    });
}

fn subscribe_shared_udp(
    state: Data<AppState>,
    addr: SocketAddrV4,
    if_name: Option<String>,
) -> Result<SharedProxyReceiver, HttpResponse> {
    let key = shared_udp_key(&addr, if_name.as_deref());
    if let Ok(shared) = state.shared_proxies.lock()
        && let Some(hub) = shared.get(&key)
    {
        return Ok(hub.subscribe());
    }

    let permit = match state.proxy_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Err(HttpResponse::ServiceUnavailable().body("Too many active proxy streams"));
        }
    };
    let hub = Arc::new(SharedProxyHub::new());
    {
        let mut shared = match state.shared_proxies.lock() {
            Ok(shared) => shared,
            Err(_) => {
                return Err(HttpResponse::InternalServerError().body("Shared proxy lock poisoned"));
            }
        };
        if let Some(existing) = shared.get(&key).cloned() {
            return Ok(existing.subscribe());
        }
        shared.insert(key.clone(), Arc::clone(&hub));
    }
    let stream = proxy::udp_source(addr, if_name, permit);
    let receiver = hub.subscribe();
    spawn_shared_proxy_task(state, key, hub, stream);
    Ok(receiver)
}

fn to_xmltv_time(unix_time: i64) -> Result<String> {
    match Utc.timestamp_millis_opt(unix_time) {
        chrono::LocalResult::Single(t) => Ok(t
            .with_timezone(&FixedOffset::east_opt(8 * 60 * 60).ok_or(anyhow!(""))?)
            .format("%Y%m%d%H%M%S")
            .to_string()),
        _ => Err(anyhow!("fail to parse time")),
    }
}

fn to_xmltv(channels: Vec<Channel>, extra: Vec<EventReader<Cursor<String>>>) -> Result<String> {
    let mut buf = BufWriter::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut buf);
    writer.write(
        XmlWriteEvent::start_element("tv")
            .attr("generator-info-name", "iptv-proxy")
            .attr("source-info-name", "iptv-proxy"),
    )?;
    for channel in channels.iter() {
        writer.write(
            XmlWriteEvent::start_element("channel").attr("id", &format!("{}", channel.id)),
        )?;
        writer.write(XmlWriteEvent::start_element("display-name"))?;
        writer.write(XmlWriteEvent::characters(&channel.name))?;
        writer.write(XmlWriteEvent::end_element())?;
        writer.write(XmlWriteEvent::end_element())?;
    }
    // For each extra xml reader, iterate its events and copy allowed tags
    for reader in extra {
        for e in reader {
            match e {
                Ok(XmlReadEvent::StartElement {
                    name, attributes, ..
                }) => {
                    let name = name.to_string();
                    let name = name.as_str();
                    if name != "channel"
                        && name != "display-name"
                        && name != "desc"
                        && name != "title"
                        && name != "sub-title"
                        && name != "programme"
                    {
                        continue;
                    }
                    let name = if name == "title" {
                        let mut iter = attributes.iter();
                        loop {
                            let attr = iter.next();
                            if attr.is_none() {
                                break "title";
                            }
                            let attr = attr.unwrap();
                            if attr.name.to_string() == "lang" && attr.value != "chi" {
                                break "title_extra";
                            }
                        }
                    } else {
                        name
                    };
                    let mut tag = XmlWriteEvent::start_element(name);
                    for attr in attributes.iter() {
                        tag = tag.attr(attr.name.borrow(), &attr.value);
                    }
                    writer.write(tag)?;
                }
                Ok(XmlReadEvent::Characters(content)) => {
                    writer.write(XmlWriteEvent::characters(&content))?;
                }
                Ok(XmlReadEvent::EndElement { name }) => {
                    let name = name.to_string();
                    let name = name.as_str();
                    if name != "channel"
                        && name != "display-name"
                        && name != "desc"
                        && name != "title"
                        && name != "sub-title"
                        && name != "programme"
                    {
                        continue;
                    }
                    writer.write(XmlWriteEvent::end_element())?;
                }
                _ => {}
            }
        }
    }
    for channel in channels.iter() {
        for epg in channel.epg.iter() {
            writer.write(
                XmlWriteEvent::start_element("programme")
                    .attr("start", &format!("{} +0800", to_xmltv_time(epg.start)?))
                    .attr("stop", &format!("{} +0800", to_xmltv_time(epg.stop)?))
                    .attr("channel", &format!("{}", channel.id)),
            )?;
            writer.write(XmlWriteEvent::start_element("title").attr("lang", "chi"))?;
            writer.write(XmlWriteEvent::characters(&epg.title))?;
            writer.write(XmlWriteEvent::end_element())?;
            if !epg.desc.is_empty() {
                writer.write(XmlWriteEvent::start_element("desc"))?;
                writer.write(XmlWriteEvent::characters(&epg.desc))?;
                writer.write(XmlWriteEvent::end_element())?;
            }
            writer.write(XmlWriteEvent::end_element())?;
        }
    }
    writer.write(XmlWriteEvent::end_element())?;
    Ok(String::from_utf8(buf.into_inner()?)?)
}

async fn fetch_extra_text(client: &Client, url: &str) -> Result<String> {
    let url = reqwest::Url::parse(url)?;
    let response = client.get(url).send().await?.error_for_status()?;
    if let Some(len) = response.content_length()
        && len > EXTRA_FETCH_MAX_BYTES as u64
    {
        return Err(anyhow!("Response too large"));
    }
    let bytes = response.bytes().await?;
    if bytes.len() > EXTRA_FETCH_MAX_BYTES {
        return Err(anyhow!("Response too large"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn parse_extra_xml(client: &Client, url: &str) -> Result<EventReader<Cursor<String>>> {
    let xml = fetch_extra_text(client, url).await?;
    let reader = Cursor::new(xml);
    Ok(EventReader::new(reader))
}

#[get("/xmltv")]
async fn xmltv(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let cache_key = format!("{}|{}", scheme, host);
    if let Some(xml) = get_cached_text(&state.xmltv_cache, &cache_key) {
        return HttpResponse::Ok().content_type("text/xml").body(xml);
    }
    // parse all extra xmltv URLs in parallel using JoinSet, collect successful readers
    let extra_readers = if !state.args.extra_xmltv.is_empty() {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_xmltv.iter().enumerate() {
            let u = u.clone();
            let client = state.extra_client.clone();
            set.spawn(async move { (i, parse_extra_xml(&client, &u).await) });
        }
        let mut readers = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((_, Ok(reader))) => readers.push(reader),
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra xmltv ({}): {}",
                    state.args.extra_xmltv[i], e
                ),
                Err(e) => warn!("Task join error parsing extra xmltv: {}", e),
            }
        }
        readers
    } else {
        Vec::new()
    };
    let xml = get_channels(&state.args, true, &scheme, &host)
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
            if let Some(old_xmltv) = OLD_XMLTV.try_lock().ok().and_then(|f| f.to_owned()) {
                HttpResponse::Ok().content_type("text/xml").body(old_xmltv)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(xml) => {
            put_cached_text(&state.xmltv_cache, cache_key, xml.clone());
            if let Ok(mut old_xmltv) = OLD_XMLTV.try_lock() {
                *old_xmltv = Some(xml.clone());
            }
            HttpResponse::Ok().content_type("text/xml").body(xml)
        }
    }
}

async fn parse_extra_playlist(client: &Client, url: &str) -> Result<String> {
    let response = fetch_extra_text(client, url).await?;
    if response.starts_with("#EXTM3U") {
        response
            .find('\n')
            .map(|i| response[i..].to_owned()) // include \n
            .ok_or(anyhow!("Empty playlist"))
    } else {
        Err(anyhow!("Playlist does not start with #EXTM3U"))
    }
}

#[get("/logo/{id}.png")]
async fn logo(state: Data<AppState>, path: Path<String>) -> impl Responder {
    debug!("Get logo");
    match get_icon(&state.args, &path).await {
        Ok(icon) => HttpResponse::Ok().content_type("image/png").body(icon),
        Err(e) => HttpResponse::NotFound().body(format!("Error getting channels: {}", e)),
    }
}

fn merge_arg(opt: Option<String>, fallback: Option<String>, default: &str) -> String {
    opt.or(fallback).unwrap_or_else(|| default.to_string())
}

fn merge_opt(opt: Option<String>, fallback: Option<String>) -> Option<String> {
    opt.or(fallback)
}

impl SharedProxyHub {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SharedProxyInner {
                chunks: VecDeque::with_capacity(SHARED_PROXY_BUFFER),
                next_seq: 0,
                receivers: 0,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn subscribe(self: &Arc<Self>) -> SharedProxyReceiver {
        let next_seq = match self.inner.lock() {
            Ok(mut inner) => {
                inner.receivers += 1;
                inner
                    .chunks
                    .front()
                    .map(|(seq, _)| *seq)
                    .unwrap_or(inner.next_seq)
            }
            Err(_) => 0,
        };
        SharedProxyReceiver {
            hub: Arc::clone(self),
            next_seq,
        }
    }

    fn receiver_count(&self) -> usize {
        self.inner.lock().map(|inner| inner.receivers).unwrap_or(0)
    }

    fn push(&self, bytes: Bytes) {
        if let Ok(mut inner) = self.inner.lock() {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.chunks.push_back((seq, bytes));
            while inner.chunks.len() > SHARED_PROXY_BUFFER {
                inner.chunks.pop_front();
            }
        }
        self.notify.notify_waiters();
    }

    fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.closed = true;
        }
        self.notify.notify_waiters();
    }
}

impl Drop for SharedProxyReceiver {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.hub.inner.lock()
            && inner.receivers > 0
        {
            inner.receivers -= 1;
        }
    }
}

impl SharedProxyReceiver {
    async fn recv(&mut self) -> Result<Bytes, SharedProxyRecvError> {
        loop {
            let notified = self.hub.notify.notified();
            {
                let inner = self
                    .hub
                    .inner
                    .lock()
                    .map_err(|_| SharedProxyRecvError::Closed)?;
                if let Some((first_seq, _)) = inner.chunks.front()
                    && self.next_seq < *first_seq
                {
                    let lagged = *first_seq - self.next_seq;
                    self.next_seq = *first_seq;
                    return Err(SharedProxyRecvError::Lagged(lagged));
                }
                if let Some((_, bytes)) = inner.chunks.iter().find(|(seq, _)| *seq == self.next_seq)
                {
                    self.next_seq += 1;
                    return Ok(bytes.clone());
                }
                if inner.closed {
                    return Err(SharedProxyRecvError::Closed);
                }
            }
            notified.await;
        }
    }
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
    })
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
    let mut index = start_index;
    for c in channels.into_iter().take(limit.unwrap_or(usize::MAX)) {
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
        index += 1;
    }
    entries
}

#[get("/playlist")]
async fn playlist_handler(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let cache_key = format!("{}|{}|{}", scheme, host, is_kodi);
    if let Some(playlist) = get_cached_text(&state.playlist_cache, &cache_key) {
        return HttpResponse::Ok()
            .content_type("application/vnd.apple.mpegurl")
            .body(playlist);
    }
    match get_channels(&state.args, false, &scheme, &host).await {
        Err(e) => {
            if let Some(old_playlist) = OLD_PLAYLIST.try_lock().ok().and_then(|f| f.to_owned()) {
                HttpResponse::Ok()
                    .content_type("application/vnd.apple.mpegurl")
                    .body(old_playlist)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(ch) => {
            let mut entries =
                build_local_entries(ch, &state.args, &scheme, &host, playseek, 0, None);
            if !state.args.extra_playlist.is_empty() {
                let mut set = JoinSet::new();
                for (i, u) in state.args.extra_playlist.iter().enumerate() {
                    let u = u.clone();
                    let client = state.extra_client.clone();
                    set.spawn(async move { (i, parse_extra_playlist(&client, &u).await) });
                }
                let mut index = entries.len();
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok((i, Ok(s))) => {
                            let source = format!("extra:{}", i);
                            let mut extra_entries = parse_m3u_playlist(&s, &source, index);
                            index += extra_entries.len();
                            entries.append(&mut extra_entries);
                        }
                        Ok((i, Err(e))) => warn!(
                            "Failed to parse extra playlist ({}): {}",
                            state.args.extra_playlist[i], e
                        ),
                        Err(e) => warn!("Task join error parsing extra playlist: {}", e),
                    }
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
            let entries = finalize_entries(entries, &ctx);
            let playlist = match render_playlist(&entries, &runtime.templates) {
                Ok(playlist) => playlist,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Template render error: {}", e));
                }
            };
            put_cached_text(&state.playlist_cache, cache_key, playlist.clone());
            if let Ok(mut old_playlist) = OLD_PLAYLIST.try_lock() {
                *old_playlist = Some(playlist.clone());
            }
            HttpResponse::Ok()
                .content_type("application/vnd.apple.mpegurl")
                .body(playlist)
        }
    }
}

#[get("/rtsp/{tail:.*}")]
async fn rtsp(
    state: Data<AppState>,
    params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    let path: String = req.match_info().query("tail").into();
    let mut param = req.query_string().to_string();
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
        param = format!("{}&playseek={}-{}", param, start, end);
    }
    let permit = match state.proxy_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return HttpResponse::ServiceUnavailable().body("Too many active proxy streams"),
    };
    HttpResponse::Ok().streaming(proxy::rtsp_source(
        format!("rtsp://{}?{}", path, param),
        state.args.interface.clone(),
        permit,
    ))
}

#[get("/manage/config")]
async fn manage_config(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let mut safe = runtime.config.clone();
    if safe.app.user.is_some() {
        safe.app.user = Some("REDACTED".to_string());
    }
    if safe.app.passwd.is_some() {
        safe.app.passwd = Some("REDACTED".to_string());
    }
    if safe.app.mac.is_some() {
        safe.app.mac = Some("REDACTED".to_string());
    }
    if !safe.auth.token.is_empty() {
        safe.auth.token = "REDACTED".to_string();
    }
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
async fn manage_index(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Manage Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
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
        alias_rules = runtime.config.alias.rules.len(),
        group_count = runtime.config.groups.entries.len(),
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
async fn manage_reload(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    drop(current);

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
    let mut runtime = match state.runtime.write() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    runtime.config = config;
    runtime.compiled = compiled;
    runtime.templates = templates;
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
    with_auth_cookie(
        &req,
        &runtime.config,
        "manage",
        HttpResponse::Ok().body("OK"),
    )
}

#[get("/manage/test")]
async fn manage_test(
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
async fn manage_channels(
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
    let channels = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let cache_key = format!(
        "{}|{}|{}|{}",
        scheme,
        host,
        is_kodi,
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
    let mut entries =
        build_local_entries(channels, &state.args, &scheme, &host, playseek, 0, limit);
    if !state.args.extra_playlist.is_empty() && limit.is_none_or(|limit| entries.len() < limit) {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_playlist.iter().enumerate() {
            let u = u.clone();
            let client = state.extra_client.clone();
            set.spawn(async move { (i, parse_extra_playlist(&client, &u).await) });
        }
        let mut index = entries.len();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((i, Ok(s))) => {
                    let source = format!("extra:{}", i);
                    let mut extra_entries = parse_m3u_playlist(&s, &source, index);
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
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra playlist ({}): {}",
                    state.args.extra_playlist[i], e
                ),
                Err(e) => warn!("Task join error parsing extra playlist: {}", e),
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
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }
    match serde_json::to_string_pretty(&entries) {
        Ok(text) => {
            put_cached_text(&state.manage_json_cache, cache_key, text.clone());
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
async fn manage_channels_raw(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let text = match get_channel_list_raw(&state.args).await {
        Ok(text) => text,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    put_cached_text(&state.manage_raw_cache, cache_key, text.clone());
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
async fn manage_channels_html(
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
    let channels = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let cache_key = format!(
        "{}|{}|{}|{}",
        scheme,
        host,
        is_kodi,
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
    let mut entries =
        build_local_entries(channels, &state.args, &scheme, &host, playseek, 0, limit);
    if !state.args.extra_playlist.is_empty() && limit.is_none_or(|limit| entries.len() < limit) {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_playlist.iter().enumerate() {
            let u = u.clone();
            let client = state.extra_client.clone();
            set.spawn(async move { (i, parse_extra_playlist(&client, &u).await) });
        }
        let mut index = entries.len();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((i, Ok(s))) => {
                    let source = format!("extra:{}", i);
                    let mut extra_entries = parse_m3u_playlist(&s, &source, index);
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
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra playlist ({}): {}",
                    state.args.extra_playlist[i], e
                ),
                Err(e) => warn!("Task join error parsing extra playlist: {}", e),
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
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = limit
        && entries.len() > limit
    {
        entries.truncate(limit);
    }

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
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
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
    );
    put_cached_text(&state.manage_html_cache, cache_key, html.clone());
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
async fn status(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
    let channels_count = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch.len(),
        Err(_) => 0,
    };
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPTV Proxy Status</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
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
        extra_playlist = state.args.extra_playlist.len(),
        extra_xmltv = state.args.extra_xmltv.len(),
        channels_count = channels_count,
        alias_rules = alias_rules,
        alias_preview = alias_preview,
        group_pills = group_pills,
        group_count = group_count,
        channels_link = channels_link,
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

#[get("/udp/{addr}")]
async fn udp(state: Data<AppState>, addr: Path<String>) -> impl Responder {
    let addr = &*addr;
    let addr = match SocketAddrV4::from_str(addr) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Error: {}", e)),
    };
    let mut receiver = match subscribe_shared_udp(state.clone(), addr, state.args.interface.clone())
    {
        Ok(receiver) => receiver,
        Err(response) => return response,
    };
    HttpResponse::Ok().streaming(stream! {
        loop {
            match receiver.recv().await {
                Ok(bytes) => yield Ok::<Bytes, anyhow::Error>(bytes),
                Err(SharedProxyRecvError::Lagged(n)) => {
                    eprintln!("UDP receiver lagged by {} packets", n);
                    warn!("UDP receiver lagged by {} packets", n);
                    continue;
                }
                Err(SharedProxyRecvError::Closed) => break,
            }
        }
    })
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
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

    let state = Data::new(AppState {
        args: effective_args.clone(),
        config_path: args.config.clone(),
        extra_client: Client::builder()
            .timeout(EXTRA_FETCH_TIMEOUT)
            .build()
            .unwrap_or_else(|e| {
                eprintln!("Failed to build extra fetch client: {}", e);
                exit(1);
            }),
        proxy_slots: Arc::new(Semaphore::new(MAX_PROXY_STREAMS)),
        shared_proxies: Mutex::new(HashMap::new()),
        playlist_cache: Mutex::new(HashMap::new()),
        xmltv_cache: Mutex::new(HashMap::new()),
        manage_json_cache: Mutex::new(HashMap::new()),
        manage_html_cache: Mutex::new(HashMap::new()),
        manage_raw_cache: Mutex::new(HashMap::new()),
        runtime: RwLock::new(RuntimeConfig {
            config,
            compiled,
            templates,
        }),
    });

    let bind_addr = effective_args.bind.clone();
    HttpServer::new(move || {
        App::new()
            .service(xmltv)
            .service(playlist_handler)
            .service(logo)
            .service(rtsp)
            .service(udp)
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
