use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
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
use tokio_util::bytes::Buf;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::fcc::{
    FccOptions, TelecomResponse, build_telecom_request, build_telecom_termination, format_hex,
    is_rtcp_packet, parse_telecom_response_with_meta,
};
use crate::rtsp_client::{KEEPALIVE_INTERVAL, RtspClient, RtspMessage};

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

fn filter_reordered_seq(seq: &mut u16, next: u16) -> bool {
    let valid = seq.wrapping_add(3000);
    if *seq == 0
        || (valid > *seq && next > *seq && next <= valid)
        || (valid < *seq && (next > *seq || next <= valid))
    {
        *seq = next;
        true
    } else {
        false
    }
}

fn seq_at_or_after(next: u16, current: u16) -> bool {
    current == 0 || (next.wrapping_sub(current) as i16) >= 0
}

fn gate_satisfied_u64(elapsed: u64, threshold: u64) -> bool {
    threshold == 0 || elapsed >= threshold
}

fn gate_satisfied_usize(count: usize, threshold: usize) -> bool {
    threshold == 0 || count >= threshold
}

fn resolve_interface_ipv4(if_name: Option<&str>) -> Result<Ipv4Addr> {
    let Some(if_name) = if_name else {
        return Ok(Ipv4Addr::new(0, 0, 0, 0));
    };
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
    warn!("interface `{if_name}` not found or has no IPv4 address, falling back to INADDR_ANY");
    Ok(Ipv4Addr::new(0, 0, 0, 0))
}

fn create_multicast_socket(multi_addr: SocketAddrV4) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    {
        socket.bind(&multi_addr.into())?;
    }
    #[cfg(target_os = "windows")]
    {
        socket.bind(&SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), multi_addr.port()).into())?;
    }
    Ok(UdpSocket::from_std(socket.into())?)
}

fn join_multicast_socket(multi_addr: SocketAddrV4, interface: Ipv4Addr) -> Result<UdpSocket> {
    let socket = create_multicast_socket(multi_addr)?;
    socket.set_multicast_loop_v4(true)?;
    socket.join_multicast_v4(*multi_addr.ip(), interface)?;
    Ok(socket)
}

fn create_fcc_socket(interface: Ipv4Addr, _if_name: Option<&str>) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
    if let Some(if_name) = _if_name {
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
    let bind_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    socket.bind(&bind_addr.into())?;
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
) -> Result<()> {
    let local_port = socket.local_addr()?.port();
    let packet = build_telecom_request(multicast_addr, local_port);
    debug!(
        target: "iptv::fcc",
        "telecom FCC request bytes=[{}]",
        format_hex(&packet)
    );
    for attempt in 1..=3 {
        socket.send_to(&packet, server).await?;
        debug!(
            target: "iptv::fcc",
            "sent telecom FCC request attempt={} multicast={} local_port={} server={}",
            attempt,
            multicast_addr,
            local_port,
            server
        );
    }
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
    for attempt in 1..=3 {
        socket.send_to(&packet, server).await?;
        debug!(
            target: "iptv::fcc",
            "sent telecom FCC termination attempt={} multicast={} server={}",
            attempt,
            multicast_addr,
            server
        );
    }
    Ok(())
}

pub(crate) fn rtsp_source(
    url: String,
    if_name: Option<String>,
    permit: OwnedSemaphorePermit,
) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let _permit = permit;
        info!("RTSP proxy {url}");
        let parsed = match Url::parse(&url) {
            Ok(url) => url,
            Err(err) => {
                error!("Invalid RTSP URL: {}", err);
                return;
            }
        };

        let mut client = match RtspClient::connect(parsed, if_name).await {
            Ok(client) => client,
            Err(err) => {
                error!("Failed to connect RTSP session: {}", err);
                return;
            }
        };

        if let Err(err) = client.describe_and_setup().await {
            error!("Failed to setup RTSP session: {}", err);
            return;
        }

        let mut seq = 0u16;
        let mut last_keepalive = tokio::time::Instant::now();

        loop {
            let wait = KEEPALIVE_INTERVAL
                .checked_sub(last_keepalive.elapsed())
                .unwrap_or_default();
            match timeout(wait, client.read_next_message()).await {
                Ok(message) => match message {
                    Ok(RtspMessage::Interleaved { channel, payload }) => {
                        if channel % 2 != 0 {
                            continue;
                        }
                        if let Ok(rtp) = RtpReader::new(payload.as_ref()) {
                            let next: u16 = rtp.sequence_number().into();
                            if filter_reordered_seq(&mut seq, next) {
                                yield Ok(Bytes::copy_from_slice(rtp.payload()));
                            }
                        }
                    }
                    Ok(RtspMessage::Response) => {}
                    Err(err) => {
                        error!("RTSP read error: {}", err);
                        break;
                    }
                },
                Err(_) => {
                    if let Err(err) = client.keepalive().await {
                        error!("RTSP keepalive failed: {}", err);
                        break;
                    }
                    last_keepalive = tokio::time::Instant::now();
                }
            }
        }
        error!("Connection closed");
    }
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
            "udp source start multicast={} interface={} fcc={:?}",
            multi_addr,
            interface,
            fcc.as_ref().map(|f| f.server)
        );

        let mut seq = 0u16;
        let mut use_multicast = true;
        let mut active_multicast_socket: Option<UdpSocket> = None;

        if let Some(fcc) = fcc {
            info!(
                target: "iptv::fcc",
                "starting telecom FCC bootstrap multicast={} server={} signaling_timeout={}ms unicast_idle_timeout={}ms max_redirects={} startup_buffer_ms={} startup_buffer_packets={} switch_extra_packets={} switch_min_unicast_ms={}",
                multi_addr,
                fcc.server,
                fcc.signaling_timeout_ms,
                fcc.unicast_idle_timeout_ms,
                fcc.max_redirects,
                fcc.startup_buffer_ms,
                fcc.startup_buffer_packets,
                fcc.switch_extra_packets,
                fcc.switch_min_unicast_ms
            );

            match create_fcc_socket(interface, if_name.as_deref()) {
                Ok(socket) => {
                    let mut server = fcc.server;
                    let mut redirects = 0usize;
                    let mut state = FccState::Requested;
                    let mut verify_server_ip = false;
                    let mut transition_multicast_socket: Option<UdpSocket> = None;
                    let mut transition_complete = false;
                    let mut mcast_buf = vec![0u8; 64 * 1024];
                    let mut termination_sent = false;
                    let mut target_switch_seq: Option<u16> = None;
                    let mut pending_multicast: VecDeque<(u16, Bytes)> = VecDeque::new();
                    let mut switch_armed_at: Option<tokio::time::Instant> = None;
                    let mut startup_unicast: VecDeque<(u16, Bytes)> = VecDeque::new();
                    let mut startup_started_at: Option<tokio::time::Instant> = None;
                    let mut startup_released = fcc.startup_buffer_ms == 0 && fcc.startup_buffer_packets == 0;
                    let mut unicast_started_at: Option<tokio::time::Instant> = None;

                    if let Ok(local_addr) = socket.local_addr() {
                        debug!(
                            target: "iptv::fcc",
                            "fcc socket bound local_addr={} multicast={}",
                            local_addr,
                            multi_addr
                        );
                    }

                    if let Err(err) = send_fcc_request(&socket, multi_addr, server).await {
                        warn!(target: "iptv::fcc", "failed to send FCC request, fallback to multicast: {}", err);
                    } else {
                        use_multicast = false;
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            let wait = match state {
                                FccState::Requested | FccState::UnicastPending => {
                                    Duration::from_millis(fcc.signaling_timeout_ms)
                                }
                                FccState::UnicastActive => {
                                    if target_switch_seq.is_some() && !pending_multicast.is_empty() {
                                        Duration::from_millis(100)
                                    } else {
                                        Duration::from_millis(fcc.unicast_idle_timeout_ms)
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
                                    if target_switch_seq.is_some() && !pending_multicast.is_empty() {
                                        let armed_ms = switch_armed_at
                                            .map(|started| started.elapsed().as_millis() as u64)
                                            .unwrap_or(0);
                                        info!(
                                            target: "iptv::fcc",
                                            "forcing multicast switchover after armed wait timeout multicast={} current_seq={} buffered_packets={} armed_ms={}",
                                            multi_addr,
                                            seq,
                                            pending_multicast.len(),
                                            armed_ms
                                        );
                                        while let Some((pending_seq, payload)) = pending_multicast.pop_front() {
                                            if filter_reordered_seq(&mut seq, pending_seq) {
                                                yield Ok(payload);
                                            }
                                        }
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
                                if let Ok(rtp) = RtpReader::new(packet) {
                                    let next: u16 = rtp.sequence_number().into();
                                    if !termination_sent {
                                        let term_seq =
                                            next.wrapping_add(fcc.switch_extra_packets as u16 + 2);
                                        if let Err(err) =
                                            send_fcc_termination(&socket, multi_addr, server, term_seq).await
                                        {
                                            debug!(
                                                target: "iptv::fcc",
                                                "failed to send FCC termination to {}: {}",
                                                server,
                                                err
                                            );
                                        } else {
                                            termination_sent = true;
                                            target_switch_seq = Some(term_seq);
                                            switch_armed_at = Some(tokio::time::Instant::now());
                                            info!(
                                                target: "iptv::fcc",
                                                "armed multicast switchover multicast={} first_mcast_seq={} target_switch_seq={} peer={}",
                                                multi_addr,
                                                next,
                                                term_seq,
                                                peer_v4
                                            );
                                        }
                                    }
                                    pending_multicast
                                        .push_back((next, Bytes::copy_from_slice(rtp.payload())));
                                    let armed_ms = switch_armed_at
                                        .map(|started| started.elapsed().as_millis() as u64)
                                        .unwrap_or(0);
                                    let unicast_elapsed_ms = unicast_started_at
                                        .map(|started| started.elapsed().as_millis() as u64)
                                        .unwrap_or(0);
                                    if let Some(target_switch_seq) = target_switch_seq
                                        && seq_at_or_after(seq, target_switch_seq)
                                        && gate_satisfied_u64(
                                            unicast_elapsed_ms,
                                            fcc.switch_min_unicast_ms,
                                        )
                                    {
                                        if !termination_sent {
                                            debug!(target: "iptv::fcc", "switch target reached without termination flag");
                                        }
                                        info!(
                                            target: "iptv::fcc",
                                            "switching from FCC unicast to multicast multicast={} current_seq={} target_switch_seq={} peer={}",
                                            multi_addr,
                                            seq,
                                            target_switch_seq,
                                            peer_v4
                                        );
                                        while let Some((pending_seq, payload)) = pending_multicast.pop_front() {
                                            if filter_reordered_seq(&mut seq, pending_seq) {
                                                yield Ok(payload);
                                            }
                                        }
                                        transition_complete = true;
                                        break;
                                    }
                                    if target_switch_seq.is_some()
                                        && !pending_multicast.is_empty()
                                        && armed_ms >= 100
                                    {
                                        info!(
                                            target: "iptv::fcc",
                                            "forcing multicast switchover from multicast side after armed wait multicast={} current_seq={} buffered_packets={} armed_ms={}",
                                            multi_addr,
                                            seq,
                                            pending_multicast.len(),
                                            armed_ms
                                        );
                                        while let Some((pending_seq, payload)) = pending_multicast.pop_front() {
                                            if filter_reordered_seq(&mut seq, pending_seq) {
                                                yield Ok(payload);
                                            }
                                        }
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
                                if verify_server_ip && peer_v4.ip() != server.ip() {
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
                                            match join_multicast_socket(multi_addr, interface) {
                                                Ok(mcast_socket) => {
                                                    info!(
                                                        target: "iptv::fcc",
                                                        "joined multicast during FCC transition multicast={} interface={}",
                                                        multi_addr,
                                                        interface
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
                                            verify_server_ip = true;
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
                                        redirects += 1;
                                        if redirects > fcc.max_redirects {
                                            warn!(
                                                target: "iptv::fcc",
                                                "fcc redirect limit exceeded redirects={} max_redirects={}, fallback to multicast",
                                                redirects,
                                                fcc.max_redirects
                                            );
                                            break;
                                        }
                                        info!(
                                            target: "iptv::fcc",
                                            "fcc redirect {} -> {} attempt={}",
                                            server,
                                            next_server,
                                            redirects
                                        );
                                        server = next_server;
                                        verify_server_ip = true;
                                        state = FccState::Requested;
                                        if let Err(err) = send_fcc_request(&socket, multi_addr, server).await {
                                            warn!(
                                                target: "iptv::fcc",
                                                "fcc redirect retry failed for server={}: {}, fallback to multicast",
                                                server,
                                                err
                                            );
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        warn!(target: "iptv::fcc", "invalid FCC response from {}: {}", peer_v4, err);
                                    }
                                }
                                continue;
                            }

                            if let Ok(rtp) = RtpReader::new(packet) {
                                let next: u16 = rtp.sequence_number().into();
                                if state != FccState::UnicastActive {
                                    info!(
                                        target: "iptv::fcc",
                                        "fcc unicast stream started multicast={} server={} first_seq={}",
                                        multi_addr,
                                        server,
                                        next
                                    );
                                    let now = tokio::time::Instant::now();
                                    startup_started_at = Some(now);
                                    unicast_started_at = Some(now);
                                }
                                state = FccState::UnicastActive;
                                let payload = Bytes::copy_from_slice(rtp.payload());
                                if !startup_released {
                                    startup_unicast.push_back((next, payload));
                                    let startup_elapsed_ms = startup_started_at
                                        .map(|started| started.elapsed().as_millis() as u64)
                                        .unwrap_or(0);
                                    if gate_satisfied_u64(startup_elapsed_ms, fcc.startup_buffer_ms)
                                        && gate_satisfied_usize(
                                            startup_unicast.len(),
                                            fcc.startup_buffer_packets,
                                        )
                                    {
                                        startup_released = true;
                                        info!(
                                            target: "iptv::fcc",
                                            "releasing buffered FCC startup burst multicast={} buffered_packets={} buffered_ms={}",
                                            multi_addr,
                                            startup_unicast.len(),
                                            startup_elapsed_ms
                                        );
                                        while let Some((buffered_seq, buffered_payload)) =
                                            startup_unicast.pop_front()
                                        {
                                            if filter_reordered_seq(&mut seq, buffered_seq) {
                                                yield Ok(buffered_payload);
                                            }
                                        }
                                    }
                                } else if filter_reordered_seq(&mut seq, next) {
                                    yield Ok(payload);
                                }
                                if let Some(target_switch_seq) = target_switch_seq
                                    && seq_at_or_after(seq, target_switch_seq)
                                    && gate_satisfied_u64(
                                        unicast_started_at
                                            .map(|started| started.elapsed().as_millis() as u64)
                                            .unwrap_or(0),
                                        fcc.switch_min_unicast_ms,
                                    )
                                {
                                    info!(
                                        target: "iptv::fcc",
                                        "switching from FCC unicast to multicast after unicast advanced current_seq={} target_switch_seq={} multicast={}",
                                        seq,
                                        target_switch_seq,
                                        multi_addr
                                    );
                                    while let Some((pending_seq, payload)) = pending_multicast.pop_front() {
                                        if filter_reordered_seq(&mut seq, pending_seq) {
                                            yield Ok(payload);
                                        }
                                    }
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
                        if transition_complete {
                            active_multicast_socket = transition_multicast_socket.take();
                        } else if !termination_sent {
                            if let Err(err) = send_fcc_termination(&socket, multi_addr, server, 0).await {
                                debug!(target: "iptv::fcc", "failed to send FCC termination to {}: {}", server, err);
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(target: "iptv::fcc", "failed to create FCC socket, fallback to multicast: {}", err);
                }
            }
        }

        let socket = match active_multicast_socket.take() {
            Some(socket) => socket,
            None => match join_multicast_socket(multi_addr, interface) {
                Ok(socket) => socket,
                Err(err) => {
                    error!("failed to join multicast {} via {}: {}", multi_addr, interface, err);
                    return;
                }
            }
        };

        if use_multicast {
            info!("Udp proxy joined {}", multi_addr);
        } else if active_multicast_socket.is_some() {
            info!(
                target: "iptv::fcc",
                "continuing on multicast after FCC switchover multicast={} interface={}",
                multi_addr,
                interface
            );
        } else {
            info!(
                target: "iptv::fcc",
                "fallback to plain multicast after FCC bootstrap multicast={} interface={}",
                multi_addr,
                interface
            );
        }

        let mut frames = UdpFramed::new(socket, BytesCodec::new());
        while let Some(item) = frames.next().await {
            match item {
                Ok((bytes, _peer)) => {
                    let mut bytes = bytes.freeze();
                    if let Ok(rtp) = RtpReader::new(bytes.as_ref()) {
                        let next = rtp.sequence_number().into();
                        bytes.advance(rtp.payload_offset());
                        if filter_reordered_seq(&mut seq, next) {
                            yield Ok(bytes);
                        }
                    }
                }
                Err(e) => {
                    error!("UDP read error: {}", e);
                    break;
                }
            }
        }

        frames
            .get_mut()
            .leave_multicast_v4(*multi_addr.ip(), interface)
            .ok();
        info!("Udp proxy left {}", multi_addr);
        error!("Connection closed");
    }
}
