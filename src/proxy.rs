use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::time::Duration;

use actix_web::web::Bytes;
use anyhow::Result;
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use local_ip_address::list_afinet_netifas;
use log::{debug, error, info, warn};
use reqwest::Url;
use rtp_rs::RtpReader;
use tokio::net::UdpSocket;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::fcc::{
    FccOptions, TelecomResponse, build_telecom_request, build_telecom_termination, format_hex,
    is_rtcp_packet, parse_telecom_response_with_meta,
};
use crate::rtsp_client::{KEEPALIVE_INTERVAL, RtspClient, RtspMessage};

const UDP_SOCKET_RECV_BUFFER: usize = 4 * 1024 * 1024;
const FCC_REQUEST_RETRY_TIMEOUT: Duration = Duration::from_millis(50);
const FCC_MAX_REQUEST_RETRIES: usize = 2;
const FCC_UNICAST_PENDING_TIMEOUT: Duration = Duration::from_millis(250);
const FCC_UNICAST_IDLE_TIMEOUT: Duration = Duration::from_millis(1000);
const FCC_ARMED_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// After a switchover is armed, hand off if the FCC unicast has produced no
/// packet for this long. The telecom server typically stops the unicast burst
/// right after the SYN (so the unicast seq never advances to the head on its
/// own); without this the loop would buffer multicast forever and freeze.
const FCC_UNICAST_STALL_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_PENDING_MULTICAST_PACKETS: usize = 4096;

const RTP_PAYLOAD_TYPE_MP2T: u8 = 33;
const SEQ_FORWARD_WINDOW: u16 = 3000;
const SEQ_RESYNC_CONSECUTIVE: u8 = 24;

const RTSP_BATCH_BYTES: usize = 16 * 1024;
const RTSP_BATCH_RESERVE_SLACK: usize = 2048;
const RTSP_BATCH_FLUSH: Duration = Duration::from_millis(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FccState {
    Requested,
    UnicastPending,
    UnicastActive,
}

enum FccEvent {
    FccTimeout,
    FccPacket(Result<(usize, SocketAddr), std::io::Error>),
    MulticastPacket(Result<(usize, SocketAddr), std::io::Error>),
}

#[derive(Clone, Debug, Default)]
struct SeqTracker {
    last: Option<u16>,
    out_of_window_prev: Option<u16>,
    out_of_window_run: u8,
}

impl SeqTracker {
    fn current(&self) -> Option<u16> {
        self.last
    }

    fn accept(&mut self, next: u16) -> bool {
        let Some(last) = self.last else {
            self.last = Some(next);
            self.out_of_window_prev = None;
            self.out_of_window_run = 0;
            return true;
        };

        let delta = next.wrapping_sub(last);
        if (1..=SEQ_FORWARD_WINDOW).contains(&delta) {
            self.last = Some(next);
            self.out_of_window_prev = None;
            self.out_of_window_run = 0;
            return true;
        }

        if self
            .out_of_window_prev
            .is_some_and(|prev| next == prev.wrapping_add(1))
        {
            self.out_of_window_prev = Some(next);
            self.out_of_window_run = self.out_of_window_run.saturating_add(1);
            if self.out_of_window_run >= SEQ_RESYNC_CONSECUTIVE {
                warn!(
                    target: "iptv::proxy",
                    "RTP sequence out-of-window resync prev_seq={} new_seq={} consecutive={}",
                    last,
                    next,
                    self.out_of_window_run
                );
                self.last = Some(next);
                self.out_of_window_prev = None;
                self.out_of_window_run = 0;
                return true;
            }
        } else {
            self.out_of_window_prev = Some(next);
            self.out_of_window_run = 1;
        }

        false
    }
}

fn parse_mpegts_rtp(packet: &[u8]) -> Option<(u16, Range<usize>)> {
    let rtp = RtpReader::new(packet).ok()?;
    let payload = rtp.payload();
    if payload.is_empty() {
        return None;
    }
    if rtp.payload_type() != RTP_PAYLOAD_TYPE_MP2T && payload[0] != 0x47 {
        return None;
    }
    let start = rtp.payload_offset();
    let end = start + payload.len();
    Some((rtp.sequence_number().into(), start..end))
}

fn seq_at_or_after(seq: u16, target: u16) -> bool {
    (seq.wrapping_sub(target) as i16) >= 0
}

fn min_unicast_satisfied(
    unicast_started_at: Option<tokio::time::Instant>,
    min_unicast_ms: u64,
) -> bool {
    min_unicast_ms == 0
        || unicast_started_at
            .is_some_and(|started| started.elapsed() >= Duration::from_millis(min_unicast_ms))
}

fn compute_handoff_gap(first_pending: Option<u16>, unicast_seq: Option<u16>) -> Option<i16> {
    first_pending
        .zip(unicast_seq)
        .map(|(first, u_seq)| first.wrapping_sub(u_seq) as i16)
}

#[derive(Debug, Eq, PartialEq)]
enum RedirectDecision {
    IgnoreDuplicate,
    Follow(SocketAddrV4),
    LimitExceeded,
}

fn evaluate_fcc_redirect(
    current_server: SocketAddrV4,
    next_server: SocketAddrV4,
    redirects: &mut usize,
    max_redirects: usize,
) -> RedirectDecision {
    if next_server == current_server {
        return RedirectDecision::IgnoreDuplicate;
    }
    *redirects += 1;
    if *redirects > max_redirects {
        RedirectDecision::LimitExceeded
    } else {
        RedirectDecision::Follow(next_server)
    }
}

fn should_ignore_fcc_peer(
    verify_server_addr: bool,
    peer: SocketAddrV4,
    expected_server: SocketAddrV4,
) -> bool {
    verify_server_addr && peer != expected_server
}

/// Decide whether to hand off from FCC unicast to multicast now, returning the
/// reason. The seamless point is when the unicast has reached the head of the
/// buffered multicast (`overlap`) and `min_unicast_ms` has been satisfied.
/// `buffer_cap`/`stall`/`deadline` are anti-freeze fallbacks.
fn fcc_switch_reason(
    unicast_seq: Option<u16>,
    first_mcast_seq: Option<u16>,
    switch_armed_at: Option<tokio::time::Instant>,
    unicast_started_at: Option<tokio::time::Instant>,
    last_unicast_at: Option<tokio::time::Instant>,
    pending_len: usize,
    min_unicast_ms: u64,
) -> Option<&'static str> {
    if pending_len == 0 {
        return None;
    }
    // Not armed yet (no multicast buffered): nothing to hand off to.
    let first = first_mcast_seq?;
    let min_ok = min_unicast_satisfied(unicast_started_at, min_unicast_ms);
    if let Some(u_seq) = unicast_seq
        && seq_at_or_after(u_seq, first)
        && min_ok
    {
        return Some("overlap");
    }
    if pending_len >= MAX_PENDING_MULTICAST_PACKETS {
        return Some("buffer_cap");
    }
    // Stall only applies once we've actually seen unicast: treating "never
    // received any unicast" as infinite idle would fire on the first multicast
    // packet and skip the FCC acceleration entirely.
    if let Some(last) = last_unicast_at
        && last.elapsed() >= FCC_UNICAST_STALL_TIMEOUT
    {
        return Some("stall");
    }
    if (min_ok || unicast_started_at.is_none())
        && switch_armed_at.is_some_and(|t| t.elapsed() >= FCC_UNICAST_IDLE_TIMEOUT)
    {
        return Some("deadline");
    }
    None
}

#[cfg(unix)]
unsafe extern "C" {
    fn if_nametoindex(ifname: *const std::ffi::c_char) -> std::ffi::c_uint;
}

#[cfg(unix)]
fn resolve_interface_index(if_name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(if_name).ok()?;
    // SAFETY: `c_name` is a valid NUL-terminated string and `if_nametoindex` is thread-safe.
    let index = unsafe { if_nametoindex(c_name.as_ptr()) };
    (index != 0).then_some(index)
}

fn resolve_interface_ipv4(if_name: Option<&str>) -> Result<Ipv4Addr> {
    let Some(if_name) = if_name else {
        return Ok(Ipv4Addr::UNSPECIFIED);
    };
    if let Ok(ip) = if_name.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let network_interfaces = list_afinet_netifas()?;
    for (name, ip) in &network_interfaces {
        debug!("interface {name}: {ip}");
        if name != if_name {
            continue;
        }
        if let IpAddr::V4(ip) = ip {
            return Ok(*ip);
        }
    }
    #[cfg(unix)]
    if let Some(index) = resolve_interface_index(if_name) {
        debug!(
            "interface `{if_name}` has no IPv4 address; will join multicast via ifindex={index}"
        );
        return Ok(Ipv4Addr::UNSPECIFIED);
    }
    warn!("interface `{if_name}` not found or has no IPv4 address, falling back to INADDR_ANY");
    Ok(Ipv4Addr::UNSPECIFIED)
}

fn create_multicast_socket(
    multi_addr: SocketAddrV4,
    if_name: Option<&str>,
) -> Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    if let Err(err) = socket.set_recv_buffer_size(UDP_SOCKET_RECV_BUFFER) {
        warn!("failed to set multicast UDP receive buffer: {}", err);
    }
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
    if let Some(if_name) = if_name
        && if_name.parse::<IpAddr>().is_err()
    {
        match socket.bind_device(Some(if_name.as_bytes())) {
            Ok(()) => {
                debug!(
                    target: "iptv::proxy",
                    "bound multicast socket to device {} via SO_BINDTODEVICE",
                    if_name
                );
            }
            Err(err) => {
                warn!(
                    target: "iptv::proxy",
                    "failed to bind multicast socket to device {}: {}, continuing with plain bind",
                    if_name,
                    err
                );
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "fuchsia")))]
    let _ = if_name;
    #[cfg(not(target_os = "windows"))]
    {
        socket.bind(&multi_addr.into())?;
    }
    #[cfg(target_os = "windows")]
    {
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, multi_addr.port()).into())?;
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn join_multicast_socket(
    multi_addr: SocketAddrV4,
    interface: Ipv4Addr,
    if_name: Option<&str>,
) -> Result<UdpSocket> {
    let socket = create_multicast_socket(multi_addr, if_name)?;
    socket.set_multicast_loop_v4(false)?;
    #[cfg(unix)]
    let joined_by_index = if let Some(name) = if_name
        && let Some(index) = resolve_interface_index(name)
    {
        let selector = socket2::InterfaceIndexOrAddress::Index(index);
        socket.join_multicast_v4_n(multi_addr.ip(), &selector)?;
        debug!(
            target: "iptv::proxy",
            "joined multicast {} on interface {} (ifindex={})",
            multi_addr,
            name,
            index
        );
        true
    } else {
        false
    };
    #[cfg(not(unix))]
    let joined_by_index = false;

    if !joined_by_index {
        socket.join_multicast_v4(multi_addr.ip(), &interface)?;
    }
    Ok(UdpSocket::from_std(socket.into())?)
}

fn leave_multicast_socket(
    socket: &UdpSocket,
    multi_addr: SocketAddrV4,
    interface: Ipv4Addr,
    if_name: Option<&str>,
) {
    #[cfg(unix)]
    if let Some(name) = if_name
        && let Some(index) = resolve_interface_index(name)
    {
        let selector = socket2::InterfaceIndexOrAddress::Index(index);
        let _ = socket2::SockRef::from(socket).leave_multicast_v4_n(multi_addr.ip(), &selector);
        return;
    }
    #[cfg(not(unix))]
    let _ = if_name;
    let _ = socket.leave_multicast_v4(*multi_addr.ip(), interface);
}

fn create_fcc_socket(interface: Ipv4Addr, if_name: Option<&str>) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    if let Err(err) = socket.set_recv_buffer_size(UDP_SOCKET_RECV_BUFFER) {
        warn!(target: "iptv::fcc", "failed to set FCC UDP receive buffer: {}", err);
    }
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
    if let Some(if_name) = if_name
        && if_name.parse::<IpAddr>().is_err()
    {
        match socket.bind_device(Some(if_name.as_bytes())) {
            Ok(()) => {
                debug!(
                    target: "iptv::fcc",
                    "bound FCC socket to device {} via SO_BINDTODEVICE",
                    if_name
                );
            }
            Err(err) => {
                warn!(
                    target: "iptv::fcc",
                    "failed to bind FCC socket to device {}: {}, continuing with plain bind",
                    if_name,
                    err
                );
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "fuchsia")))]
    let _ = if_name;
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    debug!(
        target: "iptv::fcc",
        "created FCC socket bind_addr={} resolved_interface_ip={}",
        bind_addr,
        interface
    );
    Ok(UdpSocket::from_std(socket.into())?)
}

async fn send_fcc_request(
    socket: &UdpSocket,
    multicast_addr: SocketAddrV4,
    server: SocketAddrV4,
    attempt: usize,
) -> Result<()> {
    let local_port = socket.local_addr()?.port();
    let packet = build_telecom_request(multicast_addr, local_port);
    debug!(
        target: "iptv::fcc",
        "telecom FCC request bytes=[{}]",
        format_hex(&packet)
    );
    socket.send_to(&packet, server).await?;
    debug!(
        target: "iptv::fcc",
        "sent telecom FCC request attempt={} multicast={} local_port={} server={}",
        attempt,
        multicast_addr,
        local_port,
        server
    );
    Ok(())
}

async fn send_fcc_termination(
    socket: &UdpSocket,
    multicast_addr: SocketAddrV4,
    server: SocketAddrV4,
    seqn: u16,
) -> Result<()> {
    let packet = build_telecom_termination(multicast_addr, seqn);
    debug!(
        target: "iptv::fcc",
        "telecom FCC termination bytes=[{}]",
        format_hex(&packet)
    );
    for attempt in 1..=2 {
        socket.send_to(&packet, server).await?;
        debug!(
            target: "iptv::fcc",
            "sent telecom FCC termination attempt={} multicast={} server={} seqn={}",
            attempt,
            multicast_addr,
            server,
            seqn
        );
    }
    Ok(())
}

struct FccHandoffState {
    termination_sent: bool,
    first_mcast_seq: Option<u16>,
    last_mcast_seq: Option<u16>,
    switch_armed_at: Option<tokio::time::Instant>,
    unicast_started_at: Option<tokio::time::Instant>,
    last_unicast_at: Option<tokio::time::Instant>,
}

impl FccHandoffState {
    fn new() -> Self {
        Self {
            termination_sent: false,
            first_mcast_seq: None,
            last_mcast_seq: None,
            switch_armed_at: None,
            unicast_started_at: None,
            last_unicast_at: None,
        }
    }

    async fn maybe_send_termination(
        &mut self,
        socket: &UdpSocket,
        multi_addr: SocketAddrV4,
        server: SocketAddrV4,
        fcc: &FccOptions,
    ) {
        if self.termination_sent {
            return;
        }
        let Some(mcast_seq) = self.last_mcast_seq else {
            return;
        };
        if !min_unicast_satisfied(self.unicast_started_at, fcc.switch_min_unicast_ms) {
            return;
        }
        let term_seq = mcast_seq.wrapping_add(fcc.switch_extra_packets as u16 + 2);
        match send_fcc_termination(socket, multi_addr, server, term_seq).await {
            Ok(()) => {
                self.termination_sent = true;
                self.switch_armed_at = Some(tokio::time::Instant::now());
                info!(
                    target: "iptv::fcc",
                    "armed multicast switchover multicast={} first_mcast_seq={:?} latest_mcast_seq={} target_switch_seq={}",
                    multi_addr,
                    self.first_mcast_seq,
                    mcast_seq,
                    term_seq
                );
            }
            Err(err) => {
                debug!(
                    target: "iptv::fcc",
                    "failed to send FCC termination to {}: {}",
                    server,
                    err
                );
            }
        }
    }
}

pub(crate) async fn rtsp_source(
    url: String,
    if_name: Option<String>,
    permit: OwnedSemaphorePermit,
) -> Result<impl Stream<Item = Result<Bytes>>> {
    let parsed = Url::parse(&url)?;
    info!(
        "RTSP proxy host={} port={}",
        parsed.host_str().unwrap_or("unknown"),
        parsed.port_or_known_default().unwrap_or(554)
    );
    let mut attempt = 0usize;
    let mut client = loop {
        attempt += 1;
        let error = match RtspClient::connect(parsed.clone(), if_name.clone()).await {
            Ok(mut candidate) => match candidate.describe_and_setup().await {
                Ok(()) => break candidate,
                Err(error) => error,
            },
            Err(error) => error,
        };
        if attempt >= 3 || !is_transient_rtsp_error(&error) {
            return Err(error);
        }
        let delay = if attempt == 1 {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(3)
        };
        warn!(
            "RTSP setup attempt {attempt}/3 failed with a transient error; retrying in {}s: {error}",
            delay.as_secs()
        );
        tokio::time::sleep(delay).await;
    };

    Ok(stream! {
        let _permit = permit;

        let mut seq = SeqTracker::default();
        let mut last_keepalive = tokio::time::Instant::now();
        let mut pending = BytesMut::with_capacity(RTSP_BATCH_BYTES * 2);
        let mut pending_since: Option<tokio::time::Instant> = None;

        loop {
            if !pending.is_empty()
                && pending_since.is_some_and(|started| started.elapsed() >= RTSP_BATCH_FLUSH)
            {
                pending_since = None;
                yield Ok(pending.split().freeze());
            }
            if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                if !pending.is_empty() {
                    pending_since = None;
                    yield Ok(pending.split().freeze());
                }
                if let Err(err) = client.keepalive().await {
                    error!("RTSP keepalive failed: {}", err);
                    break;
                }
                last_keepalive = tokio::time::Instant::now();
            }

            let keepalive_wait = KEEPALIVE_INTERVAL.saturating_sub(last_keepalive.elapsed());
            let wait = match pending_since {
                Some(started) => keepalive_wait.min(RTSP_BATCH_FLUSH.saturating_sub(started.elapsed())),
                None => keepalive_wait,
            };

            match timeout(wait, client.read_next_message()).await {
                Ok(Ok(RtspMessage::Interleaved { channel, payload })) => {
                    if channel % 2 != 0 {
                        continue;
                    }
                    if let Some((next, range)) = parse_mpegts_rtp(payload.as_ref())
                        && seq.accept(next)
                    {
                        if pending.is_empty() {
                            let min_cap = RTSP_BATCH_BYTES + RTSP_BATCH_RESERVE_SLACK;
                            if pending.capacity() < min_cap {
                                pending.reserve(min_cap - pending.capacity());
                            }
                            pending_since = Some(tokio::time::Instant::now());
                        }
                        pending.extend_from_slice(&payload.as_ref()[range]);
                        if pending.len() >= RTSP_BATCH_BYTES {
                            pending_since = None;
                            yield Ok(pending.split().freeze());
                        }
                    }
                }
                Ok(Ok(RtspMessage::Response)) => {}
                Ok(Err(err)) => {
                    if !pending.is_empty() {
                        yield Ok(pending.split().freeze());
                    }
                    error!("RTSP read error: {}", err);
                    break;
                }
                Err(_) => {}
            }
        }
        error!("Connection closed");
    })
}

fn is_transient_rtsp_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some()
            || cause
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
    })
}

pub(crate) fn udp_source(
    multi_addr: SocketAddrV4,
    if_name: Option<String>,
    fcc: Option<FccOptions>,
    permit: OwnedSemaphorePermit,
) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let _permit = permit;
        let interface = match resolve_interface_ipv4(if_name.as_deref()) {
            Ok(ip) => ip,
            Err(err) => {
                error!("failed to resolve interface: {}", err);
                return;
            }
        };
        debug!(
            target: "iptv::proxy",
            "udp source start multicast={} interface={} if_name={:?} fcc={:?}",
            multi_addr,
            interface,
            if_name,
            fcc.as_ref().map(|f| f.server)
        );

        let mut seq = SeqTracker::default();
        let mut use_multicast = true;
        let mut active_multicast_socket: Option<UdpSocket> = None;

        if let Some(fcc) = fcc {
            info!(
                target: "iptv::fcc",
                "starting telecom FCC bootstrap multicast={} server={} max_redirects={} switch_extra_packets={} switch_min_unicast_ms={}",
                multi_addr,
                fcc.server,
                fcc.max_redirects,
                fcc.switch_extra_packets,
                fcc.switch_min_unicast_ms
            );

            match create_fcc_socket(interface, if_name.as_deref()) {
                Ok(socket) => {
                    let mut server = fcc.server;
                    let mut redirects = 0usize;
                    let mut request_retries = 0usize;
                    let mut state = FccState::Requested;
                    let mut verify_server_addr = false;
                    let mut transition_multicast_socket: Option<UdpSocket> = None;
                    let mut transition_complete = false;
                    let mut mcast_buf = vec![0u8; 64 * 1024];
                    let mut pending_multicast: VecDeque<(u16, Bytes)> = VecDeque::new();
                    let mut handoff = FccHandoffState::new();
                    let mut switch_reason: Option<&'static str> = None;

                    if let Ok(local_addr) = socket.local_addr() {
                        debug!(
                            target: "iptv::fcc",
                            "fcc socket bound local_addr={} multicast={}",
                            local_addr,
                            multi_addr
                        );
                    }

                    if let Err(err) = send_fcc_request(&socket, multi_addr, server, 1).await {
                        warn!(target: "iptv::fcc", "failed to send FCC request, fallback to multicast: {}", err);
                    } else {
                        use_multicast = false;
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            let wait = match state {
                                FccState::Requested => FCC_REQUEST_RETRY_TIMEOUT,
                                FccState::UnicastPending => FCC_UNICAST_PENDING_TIMEOUT,
                                FccState::UnicastActive => {
                                    if !pending_multicast.is_empty() {
                                        FCC_ARMED_POLL_INTERVAL
                                    } else {
                                        FCC_UNICAST_IDLE_TIMEOUT
                                    }
                                }
                            };
                            let event = if let Some(mcast_socket) = transition_multicast_socket.as_ref() {
                                tokio::select! {
                                    recv = timeout(wait, socket.recv_from(&mut buf)) => {
                                        match recv {
                                            Ok(recv) => FccEvent::FccPacket(recv),
                                            Err(_) => FccEvent::FccTimeout,
                                        }
                                    }
                                    recv = mcast_socket.recv_from(&mut mcast_buf) => FccEvent::MulticastPacket(recv),
                                }
                            } else {
                                let recv = timeout(wait, socket.recv_from(&mut buf)).await;
                                match recv {
                                    Ok(recv) => FccEvent::FccPacket(recv),
                                    Err(_) => FccEvent::FccTimeout,
                                }
                            };

                            let (size, peer, packet, is_multicast_event) = match event {
                                FccEvent::FccTimeout => {
                                    if state == FccState::Requested && request_retries < FCC_MAX_REQUEST_RETRIES {
                                        request_retries += 1;
                                        let attempt = request_retries + 1;
                                        match send_fcc_request(&socket, multi_addr, server, attempt).await {
                                            Ok(()) => {
                                                debug!(
                                                    target: "iptv::fcc",
                                                    "retrying FCC request attempt={}/{} multicast={} server={}",
                                                    attempt,
                                                    FCC_MAX_REQUEST_RETRIES + 1,
                                                    multi_addr,
                                                    server
                                                );
                                                continue;
                                            }
                                            Err(err) => {
                                                warn!(
                                                    target: "iptv::fcc",
                                                    "FCC request retry failed for {}: {}, fallback to multicast",
                                                    server,
                                                    err
                                                );
                                                break;
                                            }
                                        }
                                    }

                                    handoff
                                        .maybe_send_termination(&socket, multi_addr, server, &fcc)
                                        .await;

                                    // Both sockets idle. If a switchover is armed, hand off
                                    // through the unified flush below (do NOT take the socket
                                    // without flushing — that would strand pending multicast
                                    // and freeze the picture).
                                    if let Some(reason) = fcc_switch_reason(
                                        seq.current(),
                                        handoff.first_mcast_seq,
                                        handoff.switch_armed_at,
                                        handoff.unicast_started_at,
                                        handoff.last_unicast_at,
                                        pending_multicast.len(),
                                        fcc.switch_min_unicast_ms,
                                    ) {
                                        switch_reason = Some(reason);
                                        transition_complete = true;
                                        break;
                                    }
                                    info!(
                                        target: "iptv::fcc",
                                        "fcc timeout state={:?} multicast={} server={}, fallback to multicast",
                                        state,
                                        multi_addr,
                                        server
                                    );
                                    break;
                                }
                                FccEvent::FccPacket(Ok((size, peer))) => (size, peer, &buf[..size], false),
                                FccEvent::FccPacket(Err(_)) => {
                                    warn!(target: "iptv::fcc", "fcc recv error, fallback to multicast");
                                    break;
                                }
                                FccEvent::MulticastPacket(Ok((size, peer))) => (size, peer, &mcast_buf[..size], true),
                                FccEvent::MulticastPacket(Err(err)) => {
                                    warn!(target: "iptv::fcc", "multicast recv error during transition: {}", err);
                                    continue;
                                }
                            };

                            if is_multicast_event {
                                let SocketAddr::V4(peer_v4) = peer else {
                                    continue;
                                };
                                if let Some((next, range)) = parse_mpegts_rtp(packet) {
                                    if handoff.first_mcast_seq.is_none() {
                                        handoff.first_mcast_seq = Some(next);
                                    }
                                    handoff.last_mcast_seq = Some(next);
                                    if handoff.switch_armed_at.is_none() {
                                        handoff.switch_armed_at = Some(tokio::time::Instant::now());
                                    }
                                    pending_multicast
                                        .push_back((next, Bytes::copy_from_slice(&packet[range])));

                                    handoff
                                        .maybe_send_termination(&socket, multi_addr, server, &fcc)
                                        .await;

                                    // Multicast packets keep arriving every few ms, so this is
                                    // where overlap (once min_unicast_ms elapses), buffer_cap,
                                    // and time-based stall/deadline fallbacks fire promptly.
                                    if let Some(reason) = fcc_switch_reason(
                                        seq.current(),
                                        handoff.first_mcast_seq,
                                        handoff.switch_armed_at,
                                        handoff.unicast_started_at,
                                        handoff.last_unicast_at,
                                        pending_multicast.len(),
                                        fcc.switch_min_unicast_ms,
                                    ) {
                                        switch_reason = Some(reason);
                                        debug!(
                                            target: "iptv::fcc",
                                            "arming handoff from multicast side multicast={} reason={} current_seq={:?} first_mcast_seq={:?} buffered={} peer={}",
                                            multi_addr,
                                            reason,
                                            seq.current(),
                                            handoff.first_mcast_seq,
                                            pending_multicast.len(),
                                            peer_v4
                                        );
                                        transition_complete = true;
                                        break;
                                    }
                                }
                                continue;
                            }

                            if is_rtcp_packet(packet) {
                                let SocketAddr::V4(peer_v4) = peer else {
                                    debug!(target: "iptv::fcc", "ignoring non-IPv4 FCC control packet from {peer}");
                                    continue;
                                };
                                debug!(
                                    target: "iptv::fcc",
                                    "received FCC control packet bytes={} peer={} state={:?}",
                                    size,
                                    peer_v4,
                                    state
                                );
                                if should_ignore_fcc_peer(verify_server_addr, peer_v4, server) {
                                    debug!(
                                        target: "iptv::fcc",
                                        "ignoring FCC RTCP from stale server peer={} expected_server={}",
                                        peer_v4,
                                        server
                                    );
                                    continue;
                                }
                                debug!(
                                    target: "iptv::fcc",
                                    "received FCC RTCP bytes=[{}] peer={}",
                                    format_hex(packet),
                                    peer_v4
                                );
                                match parse_telecom_response_with_meta(packet, server) {
                                    Ok((TelecomResponse::Ignore, meta)) => {
                                        debug!(
                                            target: "iptv::fcc",
                                            "parsed FCC control meta fmt={} result={:?} action={:?} signal_port={:?} media_port={:?} server_ip={:?}",
                                            meta.fmt,
                                            meta.result_code,
                                            meta.action_type,
                                            meta.signal_port,
                                            meta.media_port,
                                            meta.server_ip
                                        );
                                        debug!(target: "iptv::fcc", "ignored FCC control packet from {}", peer_v4);
                                    }
                                    Ok((TelecomResponse::JoinMulticast, meta)) => {
                                        debug!(
                                            target: "iptv::fcc",
                                            "parsed FCC control meta fmt={} result={:?} action={:?} signal_port={:?} media_port={:?} server_ip={:?}",
                                            meta.fmt,
                                            meta.result_code,
                                            meta.action_type,
                                            meta.signal_port,
                                            meta.media_port,
                                            meta.server_ip
                                        );
                                        info!(
                                            target: "iptv::fcc",
                                            "FCC server requested multicast or returned non-success, fallback to multicast"
                                        );
                                        break;
                                    }
                                    Ok((TelecomResponse::Sync, meta)) => {
                                        debug!(
                                            target: "iptv::fcc",
                                            "parsed FCC control meta fmt={} result={:?} action={:?} signal_port={:?} media_port={:?} server_ip={:?}",
                                            meta.fmt,
                                            meta.result_code,
                                            meta.action_type,
                                            meta.signal_port,
                                            meta.media_port,
                                            meta.server_ip
                                        );
                                        if transition_multicast_socket.is_none() {
                                            info!(
                                                target: "iptv::fcc",
                                                "FCC sync notification received, joining multicast for smooth switchover"
                                            );
                                            match join_multicast_socket(multi_addr, interface, if_name.as_deref()) {
                                                Ok(mcast_socket) => {
                                                    info!(
                                                        target: "iptv::fcc",
                                                        "joined multicast during FCC transition multicast={} interface={} if_name={:?}",
                                                        multi_addr,
                                                        interface,
                                                        if_name
                                                    );
                                                    transition_multicast_socket = Some(mcast_socket);
                                                }
                                                Err(err) => {
                                                    warn!(
                                                        target: "iptv::fcc",
                                                        "failed to join multicast during FCC transition: {}, falling back later",
                                                        err
                                                    );
                                                    break;
                                                }
                                            }
                                        } else {
                                            debug!(
                                                target: "iptv::fcc",
                                                "ignoring duplicate FCC sync notification after multicast transition is already armed"
                                            );
                                        }
                                        continue;
                                    }
                                    Ok((TelecomResponse::AwaitUnicast { server: next_server, media_port }, meta)) => {
                                        debug!(
                                            target: "iptv::fcc",
                                            "parsed FCC control meta fmt={} result={:?} action={:?} signal_port={:?} media_port={:?} server_ip={:?}",
                                            meta.fmt,
                                            meta.result_code,
                                            meta.action_type,
                                            meta.signal_port,
                                            meta.media_port,
                                            meta.server_ip
                                        );
                                        debug!(
                                            target: "iptv::fcc",
                                            "fcc accepted request server={} media_port={:?}",
                                            next_server,
                                            media_port
                                        );
                                        if next_server != server {
                                            debug!(
                                                target: "iptv::fcc",
                                                "fcc signal server updated {} -> {}",
                                                server,
                                                next_server
                                            );
                                            server = next_server;
                                            verify_server_addr = true;
                                            let _ = socket.send_to(&[], server).await;
                                        }
                                        if let Some(media_port) = media_port {
                                            let media_addr = SocketAddrV4::new(*server.ip(), media_port);
                                            debug!(
                                                target: "iptv::fcc",
                                                "probing telecom FCC media port {}",
                                                media_addr
                                            );
                                            let _ = socket.send_to(&[], media_addr).await;
                                        }
                                        if state != FccState::UnicastActive {
                                            state = FccState::UnicastPending;
                                        } else {
                                            debug!(
                                                target: "iptv::fcc",
                                                "ignoring duplicate FCC accept while unicast is already active"
                                            );
                                        }
                                    }
                                    Ok((TelecomResponse::Redirect { server: next_server }, meta)) => {
                                        debug!(
                                            target: "iptv::fcc",
                                            "parsed FCC control meta fmt={} result={:?} action={:?} signal_port={:?} media_port={:?} server_ip={:?}",
                                            meta.fmt,
                                            meta.result_code,
                                            meta.action_type,
                                            meta.signal_port,
                                            meta.media_port,
                                            meta.server_ip
                                        );
                                        match evaluate_fcc_redirect(
                                            server,
                                            next_server,
                                            &mut redirects,
                                            fcc.max_redirects,
                                        ) {
                                            RedirectDecision::IgnoreDuplicate => {
                                                debug!(
                                                    target: "iptv::fcc",
                                                    "ignoring duplicate FCC redirect to current server {}",
                                                    server
                                                );
                                                continue;
                                            }
                                            RedirectDecision::LimitExceeded => {
                                                warn!(
                                                    target: "iptv::fcc",
                                                    "fcc redirect limit exceeded redirects={} max_redirects={}, fallback to multicast",
                                                    redirects,
                                                    fcc.max_redirects
                                                );
                                                break;
                                            }
                                            RedirectDecision::Follow(target_server) => {
                                                info!(
                                                    target: "iptv::fcc",
                                                    "fcc redirect {} -> {} attempt={}",
                                                    server,
                                                    target_server,
                                                    redirects
                                                );
                                                server = target_server;
                                                verify_server_addr = true;
                                                request_retries = 0;
                                                state = FccState::Requested;
                                                if let Err(err) =
                                                    send_fcc_request(&socket, multi_addr, server, 1).await
                                                {
                                                    warn!(
                                                        target: "iptv::fcc",
                                                        "fcc redirect retry failed for server={}: {}, fallback to multicast",
                                                        server,
                                                        err
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        warn!(target: "iptv::fcc", "invalid FCC response from {}: {}", peer_v4, err);
                                    }
                                }
                                continue;
                            }

                            if let Some((next, range)) = parse_mpegts_rtp(packet) {
                                let now = tokio::time::Instant::now();
                                handoff.last_unicast_at = Some(now);
                                if state != FccState::UnicastActive {
                                    info!(
                                        target: "iptv::fcc",
                                        "fcc unicast stream started multicast={} server={} first_seq={}",
                                        multi_addr,
                                        server,
                                        next
                                    );
                                    handoff.unicast_started_at = Some(now);
                                }
                                state = FccState::UnicastActive;
                                if seq.accept(next) {
                                    yield Ok(Bytes::copy_from_slice(&packet[range]));
                                }

                                handoff
                                    .maybe_send_termination(&socket, multi_addr, server, &fcc)
                                    .await;

                                // Seamless point: once min_unicast_ms is satisfied and unicast
                                // reaches the head of buffered multicast, hand off immediately.
                                if let Some(reason) = fcc_switch_reason(
                                    seq.current(),
                                    handoff.first_mcast_seq,
                                    handoff.switch_armed_at,
                                    handoff.unicast_started_at,
                                    handoff.last_unicast_at,
                                    pending_multicast.len(),
                                    fcc.switch_min_unicast_ms,
                                ) {
                                    switch_reason = Some(reason);
                                    debug!(
                                        target: "iptv::fcc",
                                        "arming handoff from unicast side multicast={} reason={} current_seq={:?} first_mcast_seq={:?} buffered={}",
                                        multi_addr,
                                        reason,
                                        seq.current(),
                                        handoff.first_mcast_seq,
                                        pending_multicast.len()
                                    );
                                    transition_complete = true;
                                    break;
                                }
                                continue;
                            }

                            debug!(
                                target: "iptv::fcc",
                                "ignored non-RTCP/non-RTP FCC packet bytes={} peer={}",
                                size,
                                peer
                            );
                        }

                        if !handoff.termination_sent
                            && let Err(err) = send_fcc_termination(&socket, multi_addr, server, 0).await
                        {
                            debug!(
                                target: "iptv::fcc",
                                "failed to send FCC termination to {}: {}",
                                server,
                                err
                            );
                        }

                        if transition_complete {
                            // Unified flush for EVERY switch path: deliver the buffered
                            // multicast deduped against what unicast already sent, which
                            // advances `seq` to the live edge so the subsequent live read
                            // stays contiguous. (`bridge_missing` > 0 means the kernel
                            // dropped packets mid-bridge => a brief glitch.)
                            let buffered = pending_multicast.len();
                            let pre_unicast_seq = seq.current();
                            let first_pending = pending_multicast.front().map(|(s, _)| *s);
                            let last_pending = pending_multicast.back().map(|(s, _)| *s);
                            let handoff_gap = compute_handoff_gap(first_pending, pre_unicast_seq);
                            let mut delivered = 0usize;
                            let mut prev: Option<u16> = None;
                            let mut bridge_gaps = 0usize;
                            let mut bridge_missing = 0u32;
                            while let Some((pending_seq, payload)) = pending_multicast.pop_front() {
                                if let Some(p) = prev {
                                    let step = pending_seq.wrapping_sub(p);
                                    if step > 1 && step < 0x8000 {
                                        bridge_gaps += 1;
                                        bridge_missing += u32::from(step - 1);
                                    }
                                }
                                prev = Some(pending_seq);
                                if seq.accept(pending_seq) {
                                    delivered += 1;
                                    yield Ok(payload);
                                }
                            }
                            info!(
                                target: "iptv::fcc",
                                "FCC handoff flush multicast={} reason={} pre_unicast_seq={:?} current_seq={:?} first_mcast_seq={:?} handoff_gap={:?} buffered={} delivered={} first={:?} last={:?} bridge_gaps={} bridge_missing={}",
                                multi_addr,
                                switch_reason.unwrap_or("?"),
                                pre_unicast_seq,
                                seq.current(),
                                handoff.first_mcast_seq,
                                handoff_gap,
                                buffered,
                                delivered,
                                first_pending,
                                last_pending,
                                bridge_gaps,
                                bridge_missing
                            );
                            active_multicast_socket = transition_multicast_socket.take();
                        }
                    }
                }
                Err(err) => {
                    warn!(target: "iptv::fcc", "failed to create FCC socket, fallback to multicast: {}", err);
                }
            }
        }

        let switched_to_multicast = active_multicast_socket.is_some();
        let socket = match active_multicast_socket.take() {
            Some(socket) => socket,
            None => match join_multicast_socket(multi_addr, interface, if_name.as_deref()) {
                Ok(socket) => socket,
                Err(err) => {
                    error!(
                        "failed to join multicast {} via {} (if_name={:?}): {}",
                        multi_addr, interface, if_name, err
                    );
                    return;
                }
            },
        };

        if use_multicast {
            info!("Udp proxy joined {}", multi_addr);
        } else if switched_to_multicast {
            info!(
                target: "iptv::fcc",
                "continuing on multicast after FCC switchover multicast={} interface={} if_name={:?}",
                multi_addr,
                interface,
                if_name
            );
        } else {
            info!(
                target: "iptv::fcc",
                "fallback to plain multicast after FCC bootstrap multicast={} interface={} if_name={:?}",
                multi_addr,
                interface,
                if_name
            );
        }

        let mut frames = UdpFramed::new(socket, BytesCodec::new());
        while let Some(item) = frames.next().await {
            match item {
                Ok((bytes, _peer)) => {
                    let bytes = bytes.freeze();
                    if let Some((next, range)) = parse_mpegts_rtp(bytes.as_ref())
                        && seq.accept(next)
                    {
                        yield Ok(bytes.slice(range));
                    }
                }
                Err(e) => {
                    error!("UDP read error: {}", e);
                    break;
                }
            }
        }

        leave_multicast_socket(frames.get_mut(), multi_addr, interface, if_name.as_deref());
        info!("Udp proxy left {}", multi_addr);
        error!("Connection closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_packet(payload_type: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(12 + payload.len());
        pkt.push(0x80); // V=2
        pkt.push(payload_type & 0x7f);
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        pkt.extend_from_slice(&1u32.to_be_bytes()); // ssrc
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn seq_tracker_handles_zero_initial_and_u16_wraparound() {
        let mut tracker = SeqTracker::default();
        assert_eq!(tracker.current(), None);

        // Stream starting right at sequence 0 must be accepted and reject stale high packets.
        assert!(tracker.accept(0));
        assert_eq!(tracker.current(), Some(0));
        assert!(!tracker.accept(0)); // duplicate 0
        assert!(!tracker.accept(65535)); // stale packet before 0!
        assert!(!tracker.accept(65000)); // stale packet before 0!
        assert!(tracker.accept(1));

        // Now test wraparound across 65534 -> 65535 -> 0 -> 1.
        let mut wrap = SeqTracker::default();
        assert!(wrap.accept(65534));
        assert!(wrap.accept(65535));
        assert!(wrap.accept(0));
        assert_eq!(wrap.current(), Some(0));
        // Previously `*seq == 0` allowed any stale packet when seq hit 0; now rejected.
        assert!(!wrap.accept(65530));
        assert!(wrap.accept(1));
        assert_eq!(wrap.current(), Some(1));
    }

    #[test]
    fn seq_tracker_resyncs_after_24_monotonic_out_of_window_packets() {
        let mut tracker = SeqTracker::default();
        assert!(tracker.accept(50_000));

        // Non-monotonic or duplicate packets outside window must NOT resync.
        for _ in 0..30 {
            assert!(!tracker.accept(50_000));
        }
        assert_eq!(tracker.current(), Some(50_000));

        // Simulate encoder reset to 1000..=1023 (24 monotonic packets).
        for offset in 0..23u16 {
            assert!(
                !tracker.accept(1000 + offset),
                "should not resync before 24th monotonic packet (offset={offset})"
            );
        }
        assert!(
            tracker.accept(1023),
            "24th consecutive monotonic packet must trigger resync"
        );
        assert_eq!(tracker.current(), Some(1023));
        assert!(tracker.accept(1024));
    }

    #[test]
    fn parse_mpegts_rtp_filters_empty_and_noise_packets() {
        let empty = make_rtp_packet(RTP_PAYLOAD_TYPE_MP2T, 10, &[]);
        assert!(parse_mpegts_rtp(&empty).is_none());

        let noise = make_rtp_packet(96, 11, &[0x12, 0x34, 0x56, 0x78]);
        assert!(parse_mpegts_rtp(&noise).is_none());

        let mp2t_pt33 = make_rtp_packet(RTP_PAYLOAD_TYPE_MP2T, 12, &[0x00, 0x01, 0x02]);
        let (seq, range) = parse_mpegts_rtp(&mp2t_pt33).unwrap();
        assert_eq!(seq, 12);
        assert_eq!(&mp2t_pt33[range], &[0x00, 0x01, 0x02]);

        let dynamic_sync = make_rtp_packet(96, 13, &[0x47, 0x40, 0x00, 0x10]);
        let (seq2, range2) = parse_mpegts_rtp(&dynamic_sync).unwrap();
        assert_eq!(seq2, 13);
        assert_eq!(&dynamic_sync[range2], &[0x47, 0x40, 0x00, 0x10]);
    }

    #[test]
    fn fcc_switch_reason_never_fires_overlap_before_unicast_starts() {
        let now = tokio::time::Instant::now();
        // Regression test: previously seq defaulted to 0, so first_mcast_seq >= 32768
        // or first_mcast_seq == 0 caused seq_at_or_after(0, first) == true immediately!
        for first_mcast in [0u16, 1, 32768, 50000, 65535] {
            assert_eq!(
                fcc_switch_reason(None, Some(first_mcast), Some(now), None, None, 10, 0),
                None,
                "must not switch via overlap before unicast starts (first_mcast={first_mcast})"
            );
        }
        // Also verify wraparound right before target 0: u_seq=65535 is BEFORE first_mcast=0.
        assert_eq!(
            fcc_switch_reason(Some(65535), Some(0), Some(now), Some(now), Some(now), 4, 0),
            None
        );
        assert_eq!(
            fcc_switch_reason(Some(0), Some(0), Some(now), Some(now), Some(now), 4, 0),
            Some("overlap")
        );
    }

    #[test]
    fn fcc_switch_reason_gates_overlap_on_min_unicast_ms_then_switches_immediately() {
        let now = tokio::time::Instant::now();
        let started_100ms_ago = now - Duration::from_millis(100);
        let started_500ms_ago = now - Duration::from_millis(500);

        // Unicast has already caught up (u_seq=1050 >= first_mcast=1000), but only 100ms < 500ms elapsed.
        assert_eq!(
            fcc_switch_reason(
                Some(1050),
                Some(1000),
                Some(started_100ms_ago),
                Some(started_100ms_ago),
                Some(now),
                20,
                500,
            ),
            None
        );

        // As soon as 500ms has elapsed, overlap fires immediately without waiting 200ms for stall!
        assert_eq!(
            fcc_switch_reason(
                Some(1050),
                Some(1000),
                Some(started_500ms_ago),
                Some(started_500ms_ago),
                Some(now),
                20,
                500,
            ),
            Some("overlap")
        );

        // Buffer cap fires at MAX_PENDING_MULTICAST_PACKETS even if min_unicast_ms is not met yet.
        assert_eq!(
            fcc_switch_reason(
                Some(900),
                Some(1000),
                Some(started_100ms_ago),
                Some(started_100ms_ago),
                Some(now),
                MAX_PENDING_MULTICAST_PACKETS,
                5000,
            ),
            Some("buffer_cap")
        );
    }

    #[test]
    fn same_ip_port_redirect_ignores_duplicates_and_rejects_stale_port() {
        let initial: SocketAddrV4 = "10.0.0.1:8027".parse().unwrap();
        let redirected: SocketAddrV4 = "10.0.0.1:15970".parse().unwrap();
        let mut redirects = 0usize;

        assert_eq!(
            evaluate_fcc_redirect(initial, redirected, &mut redirects, 3),
            RedirectDecision::Follow(redirected)
        );
        assert_eq!(redirects, 1);

        // Duplicate redirect to the already-selected server must be ignored without incrementing count.
        assert_eq!(
            evaluate_fcc_redirect(redirected, redirected, &mut redirects, 3),
            RedirectDecision::IgnoreDuplicate
        );
        assert_eq!(redirects, 1);

        // Stale packet from 10.0.0.1:8027 (same IP, old port!) must be rejected once verify_server_addr is active.
        assert!(should_ignore_fcc_peer(true, initial, redirected));
        assert!(!should_ignore_fcc_peer(true, redirected, redirected));
    }

    #[test]
    fn handoff_gap_computes_signed_wrapping_delta() {
        assert_eq!(compute_handoff_gap(Some(105), Some(100)), Some(5));
        assert_eq!(compute_handoff_gap(Some(100), Some(105)), Some(-5));
        assert_eq!(compute_handoff_gap(Some(100), Some(100)), Some(0));
        assert_eq!(compute_handoff_gap(Some(2), Some(65535)), Some(3));
        assert_eq!(compute_handoff_gap(Some(65535), Some(2)), Some(-3));
        assert_eq!(compute_handoff_gap(Some(100), None), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_interface_index_rejects_unknown_interface() {
        assert_eq!(resolve_interface_index("nonexistent_iptv_if999"), None);
    }

    #[actix_web::test]
    async fn rtsp_source_batches_payloads_and_sends_teardown_on_drop() {
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio::sync::Semaphore;

        async fn read_req(sock: &mut tokio::net::TcpStream) -> String {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                assert!(n > 0, "unexpected EOF waiting for RTSP request");
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return String::from_utf8(buf).unwrap();
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            let req1 = read_req(&mut sock).await;
            assert!(req1.starts_with("DESCRIBE "));
            let sdp = "v=0\r\na=control:*\r\nm=video 0 RTP/AVP 33\r\na=control:track1\r\n";
            let resp1 = format!(
                "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: rtsp://{addr}/live/\r\nContent-Length: {}\r\n\r\n{}",
                sdp.len(),
                sdp
            );
            sock.write_all(resp1.as_bytes()).await.unwrap();

            let req2 = read_req(&mut sock).await;
            assert!(req2.starts_with("SETUP "));
            sock.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: sess-batch;timeout=60\r\n\r\n")
                .await
                .unwrap();

            let req3 = read_req(&mut sock).await;
            assert!(req3.starts_with("PLAY "));
            sock.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: sess-batch\r\n\r\n")
                .await
                .unwrap();

            // Send an empty RTP packet and a noise RTP packet (both ignored), followed by 15 valid 1316-byte packets.
            let mut ts_payload = [0xaa_u8; 1316];
            for chunk in ts_payload.as_chunks_mut::<188>().0 {
                chunk[0] = 0x47;
            }
            let empty_rtp = make_rtp_packet(RTP_PAYLOAD_TYPE_MP2T, 1, &[]);
            let noise_rtp = make_rtp_packet(96, 2, &[0x99; 32]);
            for ignored in [&empty_rtp, &noise_rtp] {
                let len = ignored.len() as u16;
                sock.write_all(&[b'$', 0, (len >> 8) as u8, len as u8])
                    .await
                    .unwrap();
                sock.write_all(ignored).await.unwrap();
            }

            for seq in 0..15u16 {
                let rtp = make_rtp_packet(RTP_PAYLOAD_TYPE_MP2T, seq, &ts_payload);
                let len = rtp.len() as u16;
                sock.write_all(&[b'$', 0, (len >> 8) as u8, len as u8])
                    .await
                    .unwrap();
                sock.write_all(&rtp).await.unwrap();
            }
            sock.flush().await.unwrap();

            let teardown_req = read_req(&mut sock).await;
            let _ = sock.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n").await;
            teardown_req
        });

        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.try_acquire_owned().unwrap();
        let stream = rtsp_source(format!("rtsp://user:pw@{addr}/live"), None, permit)
            .await
            .unwrap();
        let mut stream = Box::pin(stream);

        // First chunk flushes on >= 16KB threshold (13 * 1316 = 17,108 bytes).
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.len(), 13 * 1316);

        // Remaining 2 packets (2 * 1316 = 2,632 bytes) flush via 2ms timer.
        let second = timeout(Duration::from_millis(200), stream.next())
            .await
            .expect("2ms batch flush should deliver tail chunk")
            .unwrap()
            .unwrap();
        assert_eq!(second.len(), 2 * 1316);

        // Dropping the stream triggers detached best-effort TEARDOWN.
        drop(stream);

        let teardown = timeout(Duration::from_secs(1), server_task)
            .await
            .expect("mock RTSP server should receive TEARDOWN on drop")
            .unwrap();
        assert!(teardown.starts_with(&format!("TEARDOWN rtsp://{addr}/live/ RTSP/1.0\r\n")));
        assert!(teardown.contains("Session: sess-batch\r\n"));
        assert!(teardown.contains("Authorization: Basic "));
    }
}
