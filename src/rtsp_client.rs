use anyhow::{Context, Result, anyhow, bail};
use md5::compute as md5_compute;
use reqwest::Url;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_util::bytes::{Buf, Bytes, BytesMut};

const RTSP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RTSP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RTSP_TEARDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const RTSP_TCP_RECV_BUFFER: u32 = 2 * 1024 * 1024;
const RTSP_READ_BUF_CAPACITY: usize = 64 * 1024;
const MAX_RTSP_HEADER: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct RtspResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct RtspStatusError {
    pub(crate) status_code: u16,
    method: String,
    uri: String,
}

impl fmt::Display for RtspStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RTSP {} {} failed with {}",
            self.method,
            sanitized_uri(&self.uri),
            self.status_code
        )
    }
}

impl std::error::Error for RtspStatusError {}

#[derive(Clone, Debug)]
enum AuthKind {
    Basic,
    Digest(DigestChallenge),
}

#[derive(Clone, Debug)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    algorithm: Option<String>,
    qop: Option<String>,
}

#[derive(Clone, Debug)]
struct AuthState {
    username: String,
    password: String,
    kind: AuthKind,
    nonce_count: u32,
}

pub(crate) struct RtspClient {
    stream: Option<TcpStream>,
    read_buf: BytesMut,
    cseq: u32,
    session: Option<String>,
    auth: Option<AuthState>,
    request_url: Url,
    bind_hint: Option<String>,
    keepalive_uri: String,
    keepalive_method: KeepaliveMethod,
    teardown_uri: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum KeepaliveMethod {
    Options,
    GetParameter,
    SetParameter,
}

impl RtspClient {
    pub(crate) async fn connect(url: Url, if_name: Option<String>) -> Result<Self> {
        let stream = connect_tcp(&url, if_name.clone()).await?;
        Ok(Self::from_stream(stream, url, if_name))
    }

    fn from_stream(stream: TcpStream, url: Url, if_name: Option<String>) -> Self {
        Self {
            stream: Some(stream),
            read_buf: BytesMut::with_capacity(RTSP_READ_BUF_CAPACITY),
            cseq: 1,
            session: None,
            auth: auth_from_url(&url),
            request_url: url,
            bind_hint: if_name,
            keepalive_uri: "*".to_string(),
            keepalive_method: KeepaliveMethod::Options,
            teardown_uri: None,
        }
    }

    fn stream_mut(&mut self) -> Result<&mut TcpStream> {
        self.stream
            .as_mut()
            .ok_or_else(|| anyhow!("RTSP connection already closed"))
    }

    pub(crate) async fn describe_and_setup(&mut self) -> Result<()> {
        let request_url = self.request_url.to_string();
        let describe = self
            .request(
                "DESCRIBE",
                &request_url,
                &[("Accept", "application/sdp")],
                None,
            )
            .await?;
        let body = String::from_utf8(describe.body).context("invalid SDP body")?;
        let content_base = describe
            .headers
            .get("content-base")
            .or_else(|| describe.headers.get("content-location"))
            .cloned()
            .unwrap_or_else(|| self.request_url.as_str().to_string());

        let presentation = parse_sdp_presentation(&body, &self.request_url, &content_base)?;
        if presentation.tracks.is_empty() {
            bail!("no RTSP media tracks found in SDP");
        }
        log::info!(
            target: "iptv::proxy",
            "RTSP presentation control={}, tracks={:?}",
            presentation.control, presentation.tracks
        );

        self.teardown_uri = Some(presentation.control.clone());
        for (index, track) in presentation.tracks.iter().enumerate() {
            let interleaved = format!(
                "RTP/AVP/TCP;unicast;interleaved={}-{}",
                index * 2,
                index * 2 + 1
            );
            let _ = self
                .request("SETUP", track, &[("Transport", interleaved.as_str())], None)
                .await?;
        }

        self.keepalive_uri = presentation.base_url.clone();
        let play_url = presentation.control;
        let play = self
            .request("PLAY", &play_url, &[("Range", "npt=0.000-")], None)
            .await?;
        log_play_response(&play.headers);
        Ok(())
    }

    pub(crate) async fn read_next_message(&mut self) -> Result<RtspMessage> {
        self.ensure_buffered(1).await?;
        if self.read_buf[0] == b'$' {
            self.ensure_buffered(4).await?;
            let channel = self.read_buf[1];
            let len = u16::from_be_bytes([self.read_buf[2], self.read_buf[3]]) as usize;
            self.ensure_buffered(4 + len).await?;
            self.read_buf.advance(4);
            let payload = self.read_buf.split_to(len).freeze();
            Ok(RtspMessage::Interleaved { channel, payload })
        } else {
            self.read_response().await.map(|_| RtspMessage::Response)
        }
    }

    pub(crate) async fn keepalive(&mut self) -> Result<()> {
        let keepalive_uri = self.keepalive_uri.clone();
        let method = self.keepalive_method.as_str();
        let response = self.request(method, &keepalive_uri, &[], None).await?;
        if matches!(self.keepalive_method, KeepaliveMethod::Options) {
            self.update_keepalive_method(&response.headers);
        }
        Ok(())
    }

    fn update_keepalive_method(&mut self, headers: &HashMap<String, String>) {
        let Some(public) = headers.get("public") else {
            return;
        };
        let mut supports_set_parameter = false;
        let mut supports_get_parameter = false;
        for method in public.split(',').map(str::trim) {
            if method.eq_ignore_ascii_case("SET_PARAMETER") {
                supports_set_parameter = true;
            } else if method.eq_ignore_ascii_case("GET_PARAMETER") {
                supports_get_parameter = true;
            }
        }

        self.keepalive_method = if supports_set_parameter {
            KeepaliveMethod::SetParameter
        } else if supports_get_parameter {
            KeepaliveMethod::GetParameter
        } else {
            KeepaliveMethod::Options
        };
        log::info!(
            target: "iptv::proxy",
            "RTSP keepalive method selected={}",
            self.keepalive_method.as_str()
        );
    }

    async fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<RtspResponse> {
        let mut current_uri = uri.to_string();
        let mut redirects_left = if method == "DESCRIBE" { 4 } else { 0 };

        loop {
            let response = timeout(
                RTSP_REQUEST_TIMEOUT,
                self.request_inner(method, &current_uri, headers, body),
            )
            .await
            .with_context(|| format!("RTSP {method} timed out"))??;
            if response.status_code == 401 {
                let Some(www_auth) = response.headers.get("www-authenticate").cloned() else {
                    return Err(status_error(method, &current_uri, 401));
                };
                let Some(current) = self.auth.clone() else {
                    return Err(status_error(method, &current_uri, 401));
                };

                let kind = parse_auth_challenge(&www_auth)?;
                self.auth = Some(AuthState { kind, ..current });

                let retry = timeout(
                    RTSP_REQUEST_TIMEOUT,
                    self.request_inner(method, &current_uri, headers, body),
                )
                .await
                .with_context(|| format!("RTSP authenticated {method} timed out"))??;
                return ensure_success(method, &current_uri, retry);
            }

            if method == "DESCRIBE" && is_redirect_status(response.status_code) {
                if redirects_left == 0 {
                    bail!("RTSP DESCRIBE exceeded redirect limit");
                }
                redirects_left -= 1;
                let location = response
                    .headers
                    .get("location")
                    .ok_or_else(|| anyhow!("RTSP redirect missing Location header"))?;
                self.follow_redirect(location).await?;
                current_uri = self.request_url.to_string();
                continue;
            }

            return ensure_success(method, &current_uri, response);
        }
    }

    async fn follow_redirect(&mut self, location: &str) -> Result<()> {
        let redirected = if let Ok(url) = Url::parse(location) {
            url
        } else {
            self.request_url.join(location)?
        };
        let origin_changed = self.request_url.scheme() != redirected.scheme()
            || self.request_url.host_str() != redirected.host_str()
            || self.request_url.port_or_known_default() != redirected.port_or_known_default();
        log::info!(
            target: "iptv::proxy",
            "RTSP redirect {} -> {}",
            sanitized_url(&self.request_url),
            sanitized_url(&redirected)
        );
        let stream = connect_tcp(&redirected, self.bind_hint.clone()).await?;
        self.stream = Some(stream);
        self.read_buf.clear();
        self.cseq = 1;
        self.session = None;
        self.request_url = redirected;
        self.keepalive_uri = "*".to_string();
        self.keepalive_method = KeepaliveMethod::Options;
        self.teardown_uri = None;
        if origin_changed || !self.request_url.username().is_empty() {
            self.auth = auth_from_url(&self.request_url);
        }
        Ok(())
    }

    async fn request_inner(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<RtspResponse> {
        let body = body.unwrap_or_default();
        let cseq = self.cseq;
        self.cseq += 1;

        let mut req =
            format!("{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: rust-iptv-proxy\r\n");
        if let Some(session) = self.session.as_deref() {
            req.push_str(&format!("Session: {session}\r\n"));
        }
        if let Some(auth) = self.auth.as_mut() {
            let value = build_auth_header(auth, method, uri)?;
            req.push_str(&format!("Authorization: {value}\r\n"));
        }
        for (name, value) in headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");

        {
            let stream = self.stream_mut()?;
            stream.write_all(req.as_bytes()).await?;
            if !body.is_empty() {
                stream.write_all(body).await?;
            }
            stream.flush().await?;
        }
        log::info!(target: "iptv::proxy", "RTSP {} {}", method, sanitized_uri(uri));

        let response = self.read_response().await?;
        log::info!(
            target: "iptv::proxy",
            "RTSP {} {} -> {} session={:?} content-base={:?}",
            method,
            sanitized_uri(uri),
            response.status_code,
            response.headers.get("session"),
            response
                .headers
                .get("content-base")
                .or_else(|| response.headers.get("content-location"))
        );
        if let Some(session) = response.headers.get("session") {
            self.session = Some(
                session
                    .split(';')
                    .next()
                    .unwrap_or(session)
                    .trim()
                    .to_string(),
            );
        }
        Ok(response)
    }

    async fn ensure_buffered(&mut self, needed: usize) -> Result<()> {
        while self.read_buf.len() < needed {
            let additional = needed.saturating_sub(self.read_buf.len()).max(8192);
            self.read_buf.reserve(additional);
            let stream = self
                .stream
                .as_mut()
                .ok_or_else(|| anyhow!("RTSP connection already closed"))?;
            let n = stream.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                bail!("RTSP connection closed");
            }
        }
        Ok(())
    }

    async fn read_response(&mut self) -> Result<RtspResponse> {
        let header_end = loop {
            self.ensure_buffered(1).await?;
            if self.read_buf[0] == b'$' {
                self.ensure_buffered(4).await?;
                let len = u16::from_be_bytes([self.read_buf[2], self.read_buf[3]]) as usize;
                self.ensure_buffered(4 + len).await?;
                log::warn!(
                    target: "iptv::proxy",
                    "RTSP ignoring interleaved data while awaiting RTSP response"
                );
                self.read_buf.advance(4 + len);
                continue;
            }
            if let Some(pos) = find_double_crlf(&self.read_buf) {
                break pos;
            }
            if self.read_buf.len() >= MAX_RTSP_HEADER {
                bail!("RTSP response header exceeds {MAX_RTSP_HEADER} bytes");
            }
            let next_needed = self.read_buf.len() + 1;
            self.ensure_buffered(next_needed).await?;
        };

        let header_bytes = &self.read_buf[..header_end];
        let header_text = String::from_utf8_lossy(header_bytes);
        let mut lines = header_text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| anyhow!("missing RTSP status line"))?;
        let mut parts = status_line.splitn(3, ' ');
        let proto = parts.next().unwrap_or_default();
        if !proto.starts_with("RTSP/") {
            bail!("unexpected RTSP response: {status_line}");
        }
        let status_code = parts
            .next()
            .ok_or_else(|| anyhow!("missing RTSP status code"))?
            .parse::<u16>()?;

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let content_len = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if content_len > MAX_RTSP_BODY {
            bail!("RTSP response body too large: {content_len} bytes");
        }
        let total_len = header_end + 4 + content_len;
        self.ensure_buffered(total_len).await?;
        self.read_buf.advance(header_end + 4);
        let body = if content_len == 0 {
            Vec::new()
        } else {
            self.read_buf.split_to(content_len).to_vec()
        };

        Ok(RtspResponse {
            status_code,
            headers,
            body,
        })
    }
}

impl Drop for RtspClient {
    fn drop(&mut self) {
        let (Some(session), Some(mut stream)) = (self.session.take(), self.stream.take()) else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let uri = self
            .teardown_uri
            .take()
            .unwrap_or_else(|| self.request_url.to_string());
        let cseq = self.cseq;
        self.cseq += 1;
        let req = build_teardown_request(&uri, cseq, &session, self.auth.as_mut());
        let safe_uri = sanitized_uri(&uri);

        handle.spawn(async move {
            let _ = timeout(RTSP_TEARDOWN_TIMEOUT, async move {
                if stream.write_all(req.as_bytes()).await.is_ok() {
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                    let mut discard = [0u8; 1024];
                    let mut drained = 0usize;
                    while drained < 256 * 1024 {
                        match stream.read(&mut discard).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => drained += n,
                        }
                    }
                }
            })
            .await;
            log::debug!(
                target: "iptv::proxy",
                "RTSP best-effort TEARDOWN completed for {}",
                safe_uri
            );
        });
    }
}

fn build_teardown_request(
    uri: &str,
    cseq: u32,
    session: &str,
    auth: Option<&mut AuthState>,
) -> String {
    let mut req = format!(
        "TEARDOWN {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: rust-iptv-proxy\r\nSession: {session}\r\n"
    );
    if let Some(auth) = auth
        && let Ok(value) = build_auth_header(auth, "TEARDOWN", uri)
    {
        req.push_str(&format!("Authorization: {value}\r\n"));
    }
    req.push_str("\r\n");
    req
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RtspMessage {
    Response,
    Interleaved { channel: u8, payload: Bytes },
}

async fn connect_tcp(url: &Url, if_name: Option<String>) -> Result<TcpStream> {
    let host = url.host_str().ok_or_else(|| anyhow!("missing RTSP host"))?;
    let port = url.port().unwrap_or(554);
    let mut last_err = None;
    let bind_target = resolve_bind_target(if_name.as_deref());

    for addr in lookup_host((host, port)).await? {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        if let Err(err) = socket.set_nodelay(true) {
            log::warn!(target: "iptv::proxy", "failed to set RTSP TCP_NODELAY: {err}");
        }
        if let Err(err) = socket.set_recv_buffer_size(RTSP_TCP_RECV_BUFFER) {
            log::warn!(target: "iptv::proxy", "failed to set RTSP TCP receive buffer: {err}");
        }
        match &bind_target {
            Some(BindTarget::Ip(local_ip)) if local_ip.is_ipv4() == addr.is_ipv4() => {
                let bind_addr = SocketAddr::new(*local_ip, 0);
                socket.bind(bind_addr)?;
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Some(BindTarget::Device(device)) => {
                socket.bind_device(Some(device.as_bytes()))?;
            }
            _ => {}
        }
        match timeout(RTSP_CONNECT_TIMEOUT, socket.connect(addr)).await {
            Ok(Ok(stream)) => {
                log::info!(
                    target: "iptv::proxy",
                    "RTSP connected local={:?} remote={}",
                    stream.local_addr().ok(),
                    addr
                );
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Some(anyhow::Error::from(err)),
            Err(_) => last_err = Some(anyhow!("RTSP connect to {addr} timed out")),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("failed to resolve RTSP server")))
}

enum BindTarget {
    Ip(IpAddr),
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    Device(String),
}

fn resolve_bind_target(if_name: Option<&str>) -> Option<BindTarget> {
    let if_name = if_name?;

    if let Ok(ip) = if_name.parse::<IpAddr>() {
        return Some(BindTarget::Ip(ip));
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        Some(BindTarget::Device(if_name.to_string()))
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    {
        if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
            for (name, ip) in interfaces {
                if name == if_name {
                    return Some(BindTarget::Ip(ip));
                }
            }
        }
        None
    }
}

fn ensure_success(method: &str, uri: &str, response: RtspResponse) -> Result<RtspResponse> {
    if (200..300).contains(&response.status_code) {
        Ok(response)
    } else {
        Err(status_error(method, uri, response.status_code))
    }
}

fn status_error(method: &str, uri: &str, status_code: u16) -> anyhow::Error {
    RtspStatusError {
        status_code,
        method: method.to_string(),
        uri: uri.to_string(),
    }
    .into()
}

pub(crate) fn is_auth_status(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RtspStatusError>()
        .is_some_and(|error| matches!(error.status_code, 401 | 403))
}

fn is_redirect_status(status_code: u16) -> bool {
    matches!(status_code, 301 | 302 | 303 | 305 | 307 | 308)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

struct SdpPresentation {
    base_url: String,
    control: String,
    tracks: Vec<String>,
}

fn parse_sdp_presentation(
    body: &str,
    request_url: &Url,
    content_base: &str,
) -> Result<SdpPresentation> {
    let base = Url::parse(content_base).unwrap_or_else(|_| request_url.clone());
    let mut presentation_control = resolve_control_url(&base, request_url, "*")?;
    let mut tracks = Vec::new();
    let mut in_media = false;
    let mut current_media: Option<String> = None;

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            if in_media {
                if let Some(track) = current_media.take() {
                    tracks.push(resolve_control_url(&base, request_url, &track)?);
                } else {
                    tracks.push(presentation_control.clone());
                }
            }
            in_media = true;
            current_media = None;
            continue;
        }
        if let Some(control) = line.strip_prefix("a=control:") {
            let control = control.trim();
            if !in_media {
                presentation_control = resolve_control_url(&base, request_url, control)?;
                continue;
            }
            current_media = Some(control.to_string());
        }
    }

    if let Some(track) = current_media.take() {
        tracks.push(resolve_control_url(&base, request_url, &track)?);
    } else if in_media && tracks.is_empty() {
        tracks.push(presentation_control.clone());
    }

    Ok(SdpPresentation {
        base_url: base.to_string(),
        control: presentation_control,
        tracks,
    })
}

fn resolve_control_url(base: &Url, request_url: &Url, control: &str) -> Result<String> {
    if control == "*" {
        return Ok(base.to_string());
    }
    if control.starts_with("rtsp://") || control.starts_with("rtsps://") {
        let mut url = Url::parse(control)?;
        if url.query().is_none()
            && let Some(query) = base.query().or_else(|| request_url.query())
        {
            url.set_query(Some(query));
        }
        return Ok(url.to_string());
    }
    if let Some((path, query)) = control.split_once('?') {
        let mut url = join_control_url(base, request_url, path)?;
        url.set_query(Some(query));
        return Ok(url.to_string());
    }
    if control.starts_with('/') {
        let mut root = request_url.clone();
        root.set_path(control);
        if root.query().is_none() {
            root.set_query(base.query());
        }
        return Ok(root.to_string());
    }
    let mut joined = join_control_url(base, request_url, control)?;
    if joined.query().is_none()
        && let Some(query) = base.query().or_else(|| request_url.query())
    {
        joined.set_query(Some(query));
    }
    Ok(joined.to_string())
}

fn join_control_url(base: &Url, request_url: &Url, control: &str) -> Result<Url> {
    let mut joined = if base.as_str().is_empty() {
        request_url.clone()
    } else {
        base.clone()
    };
    let mut path = joined.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(control);
    joined.set_path(&path);
    Ok(joined)
}

fn auth_from_url(url: &Url) -> Option<AuthState> {
    if url.username().is_empty() {
        return None;
    }
    Some(AuthState {
        username: url.username().to_string(),
        password: url.password().unwrap_or_default().to_string(),
        kind: AuthKind::Basic,
        nonce_count: 0,
    })
}

fn parse_auth_challenge(value: &str) -> Result<AuthKind> {
    if let Some(rest) = value.strip_prefix("Basic ") {
        let _ = rest;
        return Ok(AuthKind::Basic);
    }
    let Some(rest) = value.strip_prefix("Digest ") else {
        bail!("unsupported RTSP auth scheme");
    };
    log::warn!(target: "iptv::proxy", "RTSP server requested Digest auth");
    let params = parse_auth_params(rest);
    let realm = params
        .get("realm")
        .cloned()
        .ok_or_else(|| anyhow!("digest auth missing realm"))?;
    let nonce = params
        .get("nonce")
        .cloned()
        .ok_or_else(|| anyhow!("digest auth missing nonce"))?;
    Ok(AuthKind::Digest(DigestChallenge {
        realm,
        nonce,
        opaque: params.get("opaque").cloned(),
        algorithm: params.get("algorithm").cloned(),
        qop: params.get("qop").cloned(),
    }))
}

fn parse_auth_params(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in input.split(',') {
        if let Some((name, value)) = part.trim().split_once('=') {
            out.insert(
                name.trim().to_ascii_lowercase(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    out
}

fn build_auth_header(auth: &mut AuthState, method: &str, uri: &str) -> Result<String> {
    match &auth.kind {
        AuthKind::Basic => {
            let raw = format!("{}:{}", auth.username, auth.password);
            Ok(format!("Basic {}", encode_base64(raw.as_bytes())))
        }
        AuthKind::Digest(challenge) => {
            auth.nonce_count += 1;
            let nc = format!("{:08x}", auth.nonce_count);
            let cnonce = format!("{:016x}", rand::random::<u64>());
            let qop = challenge
                .qop
                .as_deref()
                .and_then(|v| v.split(',').map(str::trim).find(|v| *v == "auth"));
            let mut ha1 = format!(
                "{:x}",
                md5_compute(format!(
                    "{}:{}:{}",
                    auth.username, challenge.realm, auth.password
                ))
            );
            match challenge.algorithm.as_deref().unwrap_or("MD5") {
                algorithm if algorithm.eq_ignore_ascii_case("MD5") => {}
                algorithm if algorithm.eq_ignore_ascii_case("MD5-sess") => {
                    ha1 = format!(
                        "{:x}",
                        md5_compute(format!("{ha1}:{}:{cnonce}", challenge.nonce))
                    );
                }
                algorithm => bail!("unsupported RTSP digest algorithm {algorithm}"),
            }
            let ha2 = format!("{:x}", md5_compute(format!("{method}:{uri}")));
            let response = if let Some(qop) = qop {
                format!(
                    "{:x}",
                    md5_compute(format!(
                        "{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}",
                        challenge.nonce
                    ))
                )
            } else {
                format!(
                    "{:x}",
                    md5_compute(format!("{ha1}:{}:{ha2}", challenge.nonce))
                )
            };

            let mut header = format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
                auth.username, challenge.realm, challenge.nonce, uri, response
            );
            if let Some(qop) = qop {
                header.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
            }
            if let Some(opaque) = &challenge.opaque {
                header.push_str(&format!(", opaque=\"{opaque}\""));
            }
            if let Some(algorithm) = &challenge.algorithm {
                header.push_str(&format!(", algorithm={algorithm}"));
            }
            Ok(header)
        }
    }
}

fn sanitized_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.to_string()
}

fn sanitized_uri(uri: &str) -> String {
    Url::parse(uri)
        .map(|url| sanitized_url(&url))
        .unwrap_or_else(|_| uri.to_string())
}

fn encode_base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let block = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((block >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(block & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let block = (data[i] as u32) << 16;
            out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let block = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// Upper bound on an RTSP response body (e.g. SDP). Guards against a malformed
/// or hostile server advertising a huge Content-Length and forcing the read
/// buffer to grow without limit.
const MAX_RTSP_BODY: usize = 4 * 1024 * 1024;

impl KeepaliveMethod {
    fn as_str(self) -> &'static str {
        match self {
            KeepaliveMethod::Options => "OPTIONS",
            KeepaliveMethod::GetParameter => "GET_PARAMETER",
            KeepaliveMethod::SetParameter => "SET_PARAMETER",
        }
    }
}

fn log_play_response(headers: &HashMap<String, String>) {
    if let Some(rtp_info) = headers.get("rtp-info") {
        log::info!(target: "iptv::proxy", "RTSP PLAY RTP-Info: {rtp_info}");
    } else {
        log::warn!(target: "iptv::proxy", "RTSP PLAY response missing RTP-Info");
    }
    if let Some(range) = headers.get("range") {
        log::info!(target: "iptv::proxy", "RTSP PLAY Range: {range}");
    }
    if let Some(session) = headers.get("session") {
        log::info!(target: "iptv::proxy", "RTSP PLAY Session: {session}");
    }
    if let Some(content_base) = headers
        .get("content-base")
        .or_else(|| headers.get("content-location"))
    {
        log::info!(target: "iptv::proxy", "RTSP PLAY Content-Base: {content_base}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn digest_without_qop_uses_legacy_response_shape() {
        let mut auth = AuthState {
            username: "user".to_string(),
            password: "pass".to_string(),
            kind: AuthKind::Digest(DigestChallenge {
                realm: "realm".to_string(),
                nonce: "nonce".to_string(),
                opaque: None,
                algorithm: Some("MD5".to_string()),
                qop: None,
            }),
            nonce_count: 0,
        };

        let header = build_auth_header(&mut auth, "DESCRIBE", "rtsp://host/live").unwrap();
        assert!(!header.contains("qop="));
        assert!(!header.contains("cnonce="));
    }

    #[test]
    fn digest_with_qop_generates_random_hex_cnonce() {
        let mut auth = AuthState {
            username: "user".to_string(),
            password: "pass".to_string(),
            kind: AuthKind::Digest(DigestChallenge {
                realm: "realm".to_string(),
                nonce: "nonce".to_string(),
                opaque: Some("op".to_string()),
                algorithm: Some("MD5".to_string()),
                qop: Some("auth".to_string()),
            }),
            nonce_count: 0,
        };

        let h1 = build_auth_header(&mut auth, "SETUP", "rtsp://host/live").unwrap();
        let h2 = build_auth_header(&mut auth, "PLAY", "rtsp://host/live").unwrap();
        let params1 = parse_auth_params(h1.strip_prefix("Digest ").unwrap());
        let params2 = parse_auth_params(h2.strip_prefix("Digest ").unwrap());

        let cnonce1 = params1.get("cnonce").expect("missing cnonce");
        let cnonce2 = params2.get("cnonce").expect("missing cnonce");
        assert_eq!(cnonce1.len(), 16);
        assert!(cnonce1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(cnonce1, cnonce2);
        assert_eq!(params1.get("nc").map(String::as_str), Some("00000001"));
        assert_eq!(params2.get("nc").map(String::as_str), Some("00000002"));
    }

    #[test]
    fn sanitized_url_removes_credentials() {
        let url = Url::parse("rtsp://user:secret@example.test/live").unwrap();
        let safe = sanitized_url(&url);

        assert!(!safe.contains("user"));
        assert!(!safe.contains("secret"));
        assert!(safe.contains("example.test"));
    }

    #[test]
    fn parses_presentation_and_track_controls() {
        let request = Url::parse("rtsp://example.test/live?token=upstream").unwrap();
        let presentation = parse_sdp_presentation(
            "v=0\r\na=control:*\r\nm=video 0 RTP/AVP 33\r\na=control:track1\r\n",
            &request,
            "rtsp://example.test/live/",
        )
        .unwrap();

        assert_eq!(presentation.tracks.len(), 1);
        assert!(presentation.tracks[0].contains("track1"));
        assert!(presentation.tracks[0].contains("token=upstream"));
    }

    #[test]
    fn rejects_unsupported_digest_algorithm() {
        let mut auth = AuthState {
            username: "user".to_string(),
            password: "pass".to_string(),
            kind: AuthKind::Digest(DigestChallenge {
                realm: "realm".to_string(),
                nonce: "nonce".to_string(),
                opaque: None,
                algorithm: Some("SHA-256".to_string()),
                qop: Some("auth".to_string()),
            }),
            nonce_count: 0,
        };

        assert!(build_auth_header(&mut auth, "PLAY", "rtsp://host/live").is_err());
    }

    #[actix_web::test]
    async fn bytes_mut_parses_fragmented_interleaved_and_response_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let writer = tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            server.write_all(&[b'$', 0, 0]).await.unwrap();
            server.write_all(&[5, b'h', b'e']).await.unwrap();
            server
                .write_all(b"lloRTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            server.write_all(&[b'$', 1, 0, 3, 1, 2, 3]).await.unwrap();
            server.flush().await.unwrap();
        });

        let url = Url::parse(&format!("rtsp://{addr}/live")).unwrap();
        let mut client = RtspClient::connect(url, None).await.unwrap();

        assert_eq!(
            client.read_next_message().await.unwrap(),
            RtspMessage::Interleaved {
                channel: 0,
                payload: Bytes::from_static(b"hello"),
            }
        );
        assert_eq!(
            client.read_next_message().await.unwrap(),
            RtspMessage::Response
        );
        assert_eq!(
            client.read_next_message().await.unwrap(),
            RtspMessage::Interleaved {
                channel: 1,
                payload: Bytes::from_static(&[1, 2, 3]),
            }
        );
        writer.await.unwrap();
    }

    #[actix_web::test]
    async fn drop_sends_best_effort_teardown_with_session_and_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&tmp[..n]);
                if find_double_crlf(&received).is_some() {
                    let _ = server
                        .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n")
                        .await;
                    break;
                }
            }
            String::from_utf8(received).unwrap()
        });

        let url = Url::parse(&format!("rtsp://alice:secret@{addr}/live/ch1")).unwrap();
        let mut client = RtspClient::connect(url, None).await.unwrap();
        client.cseq = 4;
        client.session = Some("sess-42".to_string());
        client.teardown_uri = Some(format!("rtsp://{addr}/live/ch1"));
        drop(client);

        let raw_teardown = timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server should receive TEARDOWN promptly")
            .unwrap();
        assert!(raw_teardown.starts_with(&format!("TEARDOWN rtsp://{addr}/live/ch1 RTSP/1.0\r\n")));
        assert!(raw_teardown.contains("CSeq: 4\r\n"));
        assert!(raw_teardown.contains("Session: sess-42\r\n"));
        assert!(raw_teardown.contains("Authorization: Basic "));
    }
}
