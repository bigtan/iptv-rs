use anyhow::{Context, Result, anyhow, bail};
use md5::compute as md5_compute;
use reqwest::Url;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

#[derive(Clone, Debug)]
struct RtspResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

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
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    cseq: u32,
    session: Option<String>,
    auth: Option<AuthState>,
    request_url: Url,
    bind_hint: Option<String>,
    keepalive_uri: String,
    keepalive_method: KeepaliveMethod,
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
        Ok(Self {
            stream,
            read_buf: Vec::with_capacity(8192),
            read_pos: 0,
            cseq: 1,
            session: None,
            auth: auth_from_url(&url),
            request_url: url,
            bind_hint: if_name,
            keepalive_uri: "*".to_string(),
            keepalive_method: KeepaliveMethod::Options,
        })
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
        if self.read_buf[self.read_pos] == b'$' {
            self.ensure_buffered(4).await?;
            let channel = self.read_buf[self.read_pos + 1];
            let len = u16::from_be_bytes([
                self.read_buf[self.read_pos + 2],
                self.read_buf[self.read_pos + 3],
            ]) as usize;
            self.ensure_buffered(4 + len).await?;
            let start = self.read_pos + 4;
            let end = start + len;
            let payload = self.read_buf[start..end].to_vec();
            self.consume(end - self.read_pos);
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
            let response = self
                .request_inner(method, &current_uri, headers, body)
                .await?;
            if response.status_code == 401 {
                let Some(www_auth) = response.headers.get("www-authenticate").cloned() else {
                    bail!("RTSP auth required but WWW-Authenticate is missing");
                };
                let Some(current) = self.auth.clone() else {
                    bail!("RTSP auth required but URL has no credentials");
                };

                let kind = parse_auth_challenge(&www_auth)?;
                self.auth = Some(AuthState { kind, ..current });

                let retry = self
                    .request_inner(method, &current_uri, headers, body)
                    .await?;
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
        log::info!(
            target: "iptv::proxy",
            "RTSP redirect {} -> {}",
            self.request_url,
            redirected
        );
        let stream = connect_tcp(&redirected, self.bind_hint.clone()).await?;
        self.stream = stream;
        self.read_buf.clear();
        self.read_pos = 0;
        self.cseq = 1;
        self.session = None;
        self.request_url = redirected;
        self.keepalive_uri = "*".to_string();
        self.keepalive_method = KeepaliveMethod::Options;
        if self.auth.is_none() {
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
            let value = build_auth_header(auth, method, uri);
            req.push_str(&format!("Authorization: {value}\r\n"));
        }
        for (name, value) in headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");

        self.stream.write_all(req.as_bytes()).await?;
        if !body.is_empty() {
            self.stream.write_all(body).await?;
        }
        self.stream.flush().await?;
        log::info!(target: "iptv::proxy", "RTSP {} {}", method, uri);

        let response = self.read_response().await?;
        log::info!(
            target: "iptv::proxy",
            "RTSP {} {} -> {} session={:?} content-base={:?}",
            method,
            uri,
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
        while self.read_buf.len().saturating_sub(self.read_pos) < needed {
            self.compact_if_needed();
            let mut tmp = [0u8; 8192];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                bail!("RTSP connection closed");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    async fn read_response(&mut self) -> Result<RtspResponse> {
        let header_end = loop {
            self.ensure_buffered(1).await?;
            if self.read_buf[self.read_pos] == b'$' {
                self.ensure_buffered(4).await?;
                let len = u16::from_be_bytes([
                    self.read_buf[self.read_pos + 2],
                    self.read_buf[self.read_pos + 3],
                ]) as usize;
                self.ensure_buffered(4 + len).await?;
                log::warn!(
                    target: "iptv::proxy",
                    "RTSP ignoring interleaved data while awaiting RTSP response"
                );
                self.consume(4 + len);
                continue;
            }
            if let Some(pos) = find_double_crlf(&self.read_buf[self.read_pos..]) {
                break pos;
            }
            self.ensure_buffered(self.read_buf.len().saturating_sub(self.read_pos) + 1)
                .await?;
        };

        let header_bytes = &self.read_buf[self.read_pos..self.read_pos + header_end];
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
        let total_len = header_end + 4 + content_len;
        self.ensure_buffered(total_len).await?;
        let body_start = self.read_pos + header_end + 4;
        let body_end = self.read_pos + total_len;
        let body = self.read_buf[body_start..body_end].to_vec();
        self.consume(total_len);

        Ok(RtspResponse {
            status_code,
            headers,
            body,
        })
    }

    fn consume(&mut self, amount: usize) {
        self.read_pos += amount;
        self.compact_if_needed();
    }

    fn compact_if_needed(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
            return;
        }
        if self.read_pos >= 8192 || self.read_pos * 2 >= self.read_buf.len() {
            self.read_buf.copy_within(self.read_pos.., 0);
            self.read_buf.truncate(self.read_buf.len() - self.read_pos);
            self.read_pos = 0;
        }
    }
}

pub(crate) enum RtspMessage {
    Response,
    Interleaved { channel: u8, payload: Vec<u8> },
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
        match socket.connect(addr).await {
            Ok(stream) => {
                log::info!(
                    target: "iptv::proxy",
                    "RTSP connected local={:?} remote={}",
                    stream.local_addr().ok(),
                    addr
                );
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("failed to resolve RTSP server")))
}

enum BindTarget {
    Ip(IpAddr),
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    Device(String),
}

fn resolve_bind_target(if_name: Option<&str>) -> Option<BindTarget> {
    let Some(if_name) = if_name else {
        return None;
    };

    if let Ok(ip) = if_name.parse::<IpAddr>() {
        return Some(BindTarget::Ip(ip));
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        return Some(BindTarget::Device(if_name.to_string()));
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
        bail!("RTSP {method} {uri} failed with {}", response.status_code)
    }
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
    let mut media_sections = 0usize;

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            in_media = true;
            media_sections += 1;
            if let Some(track) = current_media.take() {
                tracks.push(resolve_control_url(&base, request_url, &track)?);
            } else if media_sections > 1 || tracks.is_empty() {
                tracks.push(presentation_control.clone());
            }
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
        if url.query().is_none() {
            if let Some(query) = base.query().or_else(|| request_url.query()) {
                url.set_query(Some(query));
            }
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
    if joined.query().is_none() {
        if let Some(query) = base.query().or_else(|| request_url.query()) {
            joined.set_query(Some(query));
        }
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

fn build_auth_header(auth: &mut AuthState, method: &str, uri: &str) -> String {
    match &auth.kind {
        AuthKind::Basic => {
            let raw = format!("{}:{}", auth.username, auth.password);
            format!("Basic {}", encode_base64(raw.as_bytes()))
        }
        AuthKind::Digest(challenge) => {
            auth.nonce_count += 1;
            let nc = format!("{:08x}", auth.nonce_count);
            let cnonce = format!(
                "{:x}",
                md5_compute(format!("{method}:{uri}:{nc}:{}", auth.username))
            );
            let qop = challenge
                .qop
                .as_deref()
                .and_then(|v| v.split(',').map(str::trim).find(|v| *v == "auth"))
                .unwrap_or("auth");
            let ha1 = format!(
                "{:x}",
                md5_compute(format!(
                    "{}:{}:{}",
                    auth.username, challenge.realm, auth.password
                ))
            );
            let ha2 = format!("{:x}", md5_compute(format!("{method}:{uri}")));
            let response = format!(
                "{:x}",
                md5_compute(format!(
                    "{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}",
                    challenge.nonce
                ))
            );

            let mut header = format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", qop={}, nc={}, cnonce=\"{}\"",
                auth.username, challenge.realm, challenge.nonce, uri, response, qop, nc, cnonce
            );
            if let Some(opaque) = &challenge.opaque {
                header.push_str(&format!(", opaque=\"{opaque}\""));
            }
            if let Some(algorithm) = &challenge.algorithm {
                header.push_str(&format!(", algorithm={algorithm}"));
            }
            header
        }
    }
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
