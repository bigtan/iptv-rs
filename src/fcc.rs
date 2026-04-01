use anyhow::{Result, anyhow, bail};
use std::net::{Ipv4Addr, SocketAddrV4};

const RTCP_PAYLOAD_TYPE_RTPFB: u8 = 205;
const FCC_FMT_TELECOM_REQ: u8 = 2;
const FCC_FMT_TELECOM_RESP: u8 = 3;
const FCC_FMT_TELECOM_SYN: u8 = 4;
const FCC_FMT_TELECOM_TERM: u8 = 5;

#[derive(Clone, Debug)]
pub(crate) struct FccOptions {
    pub(crate) server: SocketAddrV4,
    pub(crate) signaling_timeout_ms: u64,
    pub(crate) unicast_idle_timeout_ms: u64,
    pub(crate) max_redirects: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum TelecomResponse {
    Ignore,
    JoinMulticast,
    AwaitUnicast {
        server: SocketAddrV4,
        media_port: Option<u16>,
    },
    Redirect {
        server: SocketAddrV4,
    },
    Sync,
}

#[derive(Clone, Debug)]
pub(crate) struct TelecomResponseMeta {
    pub(crate) fmt: u8,
    pub(crate) result_code: Option<u8>,
    pub(crate) action_type: Option<u8>,
    pub(crate) signal_port: Option<u16>,
    pub(crate) media_port: Option<u16>,
    pub(crate) server_ip: Option<Ipv4Addr>,
}

pub(crate) fn parse_fcc_server(value: &str) -> Result<SocketAddrV4> {
    value
        .parse::<SocketAddrV4>()
        .map_err(|e| anyhow!("invalid FCC server `{value}`: {e}"))
}

pub(crate) fn build_telecom_request(multicast_addr: SocketAddrV4, client_port: u16) -> [u8; 40] {
    let mut packet = [0u8; 40];
    let len_words = (packet.len() / 4 - 1) as u16;
    packet[0] = 0x80 | FCC_FMT_TELECOM_REQ;
    packet[1] = RTCP_PAYLOAD_TYPE_RTPFB;
    packet[2..4].copy_from_slice(&len_words.to_be_bytes());
    packet[8..12].copy_from_slice(&multicast_addr.ip().octets());
    packet[16..18].copy_from_slice(&client_port.to_be_bytes());
    packet[18..20].copy_from_slice(&multicast_addr.port().to_be_bytes());
    packet[20..24].copy_from_slice(&multicast_addr.ip().octets());
    packet
}

pub(crate) fn build_telecom_termination(multicast_addr: SocketAddrV4, seqn: u16) -> [u8; 16] {
    let mut packet = [0u8; 16];
    let len_words = (packet.len() / 4 - 1) as u16;
    packet[0] = 0x80 | FCC_FMT_TELECOM_TERM;
    packet[1] = RTCP_PAYLOAD_TYPE_RTPFB;
    packet[2..4].copy_from_slice(&len_words.to_be_bytes());
    packet[8..12].copy_from_slice(&multicast_addr.ip().octets());
    packet[12] = if seqn == 0 { 1 } else { 0 };
    packet[14..16].copy_from_slice(&seqn.to_be_bytes());
    packet
}

pub(crate) fn format_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(3));
    for (i, byte) in data.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02X}");
    }
    out
}

pub(crate) fn is_rtcp_packet(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    let payload_type = data[1];
    if !(200..=211).contains(&payload_type) {
        return false;
    }
    let length_words = u16::from_be_bytes([data[2], data[3]]) as usize;
    let packet_len = (length_words + 1) * 4;
    packet_len > 0 && packet_len <= data.len()
}

pub(crate) fn parse_telecom_response_with_meta(
    data: &[u8],
    current_server: SocketAddrV4,
) -> Result<(TelecomResponse, TelecomResponseMeta)> {
    if data.len() < 12 {
        return Ok((
            TelecomResponse::Ignore,
            TelecomResponseMeta {
                fmt: 0,
                result_code: None,
                action_type: None,
                signal_port: None,
                media_port: None,
                server_ip: None,
            },
        ));
    }

    let fmt = data[0] & 0x1f;
    if data[1] != RTCP_PAYLOAD_TYPE_RTPFB {
        return Ok((
            TelecomResponse::Ignore,
            TelecomResponseMeta {
                fmt,
                result_code: None,
                action_type: None,
                signal_port: None,
                media_port: None,
                server_ip: None,
            },
        ));
    }

    if fmt == FCC_FMT_TELECOM_SYN {
        return Ok((
            TelecomResponse::Sync,
            TelecomResponseMeta {
                fmt,
                result_code: None,
                action_type: None,
                signal_port: None,
                media_port: None,
                server_ip: None,
            },
        ));
    }
    if fmt != FCC_FMT_TELECOM_RESP {
        return Ok((
            TelecomResponse::Ignore,
            TelecomResponseMeta {
                fmt,
                result_code: None,
                action_type: None,
                signal_port: None,
                media_port: None,
                server_ip: None,
            },
        ));
    }
    if data.len() < 36 {
        bail!("telecom FCC response too short: {}", data.len());
    }

    let result_code = data[12];
    let action_type = data[13];
    let signal_port = u16::from_be_bytes([data[14], data[15]]);
    let media_port = u16::from_be_bytes([data[16], data[17]]);
    let new_ip = Ipv4Addr::new(data[20], data[21], data[22], data[23]);

    let server_ip = if new_ip.octets() == [0, 0, 0, 0] {
        *current_server.ip()
    } else {
        new_ip
    };
    let meta = TelecomResponseMeta {
        fmt,
        result_code: Some(result_code),
        action_type: Some(action_type),
        signal_port: (signal_port != 0).then_some(signal_port),
        media_port: (media_port != 0).then_some(media_port),
        server_ip: Some(server_ip),
    };
    let signal_server = SocketAddrV4::new(
        server_ip,
        if signal_port == 0 {
            current_server.port()
        } else {
            signal_port
        },
    );

    if result_code != 0 {
        return Ok((TelecomResponse::JoinMulticast, meta));
    }

    let response = match action_type {
        1 => TelecomResponse::JoinMulticast,
        2 => TelecomResponse::AwaitUnicast {
            server: signal_server,
            media_port: (media_port != 0).then_some(media_port),
        },
        3 => TelecomResponse::Redirect {
            server: signal_server,
        },
        _ => TelecomResponse::JoinMulticast,
    };
    Ok((response, meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telecom_request_contains_multicast_and_ports() {
        let packet =
            build_telecom_request(SocketAddrV4::new(Ipv4Addr::new(239, 1, 2, 3), 5140), 40000);
        assert_eq!(packet[0] & 0x1f, FCC_FMT_TELECOM_REQ);
        assert_eq!(&packet[8..12], &[239, 1, 2, 3]);
        assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 40000);
        assert_eq!(u16::from_be_bytes([packet[18], packet[19]]), 5140);
    }

    #[test]
    fn telecom_response_redirect_is_parsed() {
        let mut packet = [0u8; 36];
        packet[0] = 0x80 | FCC_FMT_TELECOM_RESP;
        packet[1] = RTCP_PAYLOAD_TYPE_RTPFB;
        packet[12] = 0;
        packet[13] = 3;
        packet[14..16].copy_from_slice(&15970u16.to_be_bytes());
        packet[20..24].copy_from_slice(&[10, 0, 0, 2]);

        let response = parse_telecom_response(
            &packet,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12000),
        )
        .unwrap();
        match response {
            TelecomResponse::Redirect { server } => {
                assert_eq!(server, SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 15970));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
