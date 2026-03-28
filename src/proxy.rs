use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use actix_web::web::Bytes;
use anyhow::Result;
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use local_ip_address::list_afinet_netifas;
use log::{error, info};
use reqwest::Url;
use rtp_rs::RtpReader;
use tokio::net::UdpSocket;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tokio_util::bytes::Buf;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::rtsp_client::{KEEPALIVE_INTERVAL, RtspClient, RtspMessage};

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
    permit: OwnedSemaphorePermit,
) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let _permit = permit;
        let socket =  {
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
            UdpSocket::from_std(socket.into())?
        };

        let mut interface = Ipv4Addr::new(0, 0, 0, 0);
        if let Some(ref i) = if_name {
            use log::debug;
            let network_interfaces = list_afinet_netifas()?;
            for (name, ip) in network_interfaces.iter() {
                debug!("{}: {}", name, ip);
                if name != i {
                    continue;
                }
                if let IpAddr::V4(ip) = ip {
                    interface = *ip;
                    break;
                }
            }
        }

        socket.set_multicast_loop_v4(true)?;

        socket.join_multicast_v4(
            *multi_addr.ip(),
            interface,
        )?;

        info!("Udp proxy joined {}", multi_addr);

        let mut frames = UdpFramed::new(socket, BytesCodec::new());
        let mut seq = 0u16;
        while let Some(item) = frames.next().await {
            match item {
                Ok((bytes, _)) => {
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
