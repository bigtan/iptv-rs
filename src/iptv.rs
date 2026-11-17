use crate::{args::UpstreamCredentials, upstream_auth::UpstreamAuthManager};
use anyhow::{Result, anyhow};
use des::TdesEde3;
use ecb::cipher::{BlockModeEncrypt, KeyInit, block_padding::Pkcs7};
#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
use local_ip_address::list_afinet_netifas;
use log::{debug, info, warn};
use regex_lite::Regex;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinSet;

pub(crate) const DEFAULT_EDS_URL: &str = "http://eds.iptv.gd.cn:8082/EDS/jsp/AuthenticationURL";

pub(crate) fn build_client_with_if(
    #[allow(unused_variables)] if_name: Option<&str>,
) -> Result<Client> {
    let timeout = Duration::new(5, 0);
    #[allow(unused_mut)]
    let mut client = Client::builder().timeout(timeout).cookie_store(true);

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if let Some(i) = if_name {
        let network_interfaces = list_afinet_netifas()?;
        for (name, ip) in network_interfaces.iter() {
            debug!("{}: {}", name, ip);
            if name == i {
                client = client.local_address(ip.to_owned());
                break;
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(i) = if_name {
        client = client.interface(i);
    }

    Ok(client.build()?)
}

pub(crate) async fn discover_base_url(
    client: &Client,
    eds_url: &str,
    user: &str,
) -> Result<String> {
    let params = [("Action", "Login"), ("return_type", "1"), ("UserID", user)];
    let url = Url::parse_with_params(eds_url, params)?;
    let response = client.get(url).send().await?.error_for_status()?;

    let epgurl = Url::parse(response.json::<AuthJson>().await?.epgurl.as_str())?;
    let base_url = format!(
        "{}://{}:{}",
        epgurl.scheme(),
        epgurl.host_str().ok_or_else(|| anyhow!("no host"))?,
        epgurl
            .port_or_known_default()
            .ok_or_else(|| anyhow!("no port"))?,
    );
    debug!("Got base_url {base_url}");
    Ok(base_url)
}

async fn fetch_channellist_raw(
    client: &Client,
    creds: &UpstreamCredentials,
    base_url: &str,
) -> Result<String> {
    let user = creds.user.as_str();
    let passwd = creds.passwd.as_str();
    let mac = creds.mac.as_str();
    let imei = creds.imei.as_str();
    let ip = creds.address.as_str();

    let params = [
        ("response_type", "EncryToken"),
        ("client_id", "smcphone"),
        ("userid", user),
    ];
    let url = Url::parse_with_params(
        format!("{base_url}/EPG/oauth/v2/authorize").as_str(),
        params,
    )?;
    let response = client.get(url).send().await?.error_for_status()?;
    let token = response.json::<TokenJson>().await?.encry_token;

    debug!("Obtained IPTV authorization token");

    let md5_hex = format!("{:X}", md5::compute(passwd.as_bytes()));
    let enc =
        ecb::Encryptor::<TdesEde3>::new_from_slice(&md5_hex.as_bytes()[0..24]).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("Encrypt error {e}"),
            )
        })?;
    let data = format!(
        "{}${token}${user}${imei}${ip}${mac}$$CTC",
        rand::random_range(0..10000000),
    );
    let auth = hex::encode_upper(enc.encrypt_padded_vec::<Pkcs7>(data.as_bytes()));

    debug!("Built IPTV authorization response");

    let params = [
        ("client_id", "smcphone"),
        ("DeviceType", "deviceType"),
        ("UserID", user),
        ("DeviceVersion", "deviceVersion"),
        ("userdomain", "2"),
        ("datadomain", "3"),
        ("accountType", "1"),
        ("authinfo", auth.as_str()),
        ("grant_type", "EncryToken"),
    ];
    let url = Url::parse_with_params(format!("{base_url}/EPG/oauth/v2/token").as_str(), params)?;
    let _response = client.get(url).send().await?.error_for_status()?;

    let url = Url::parse(format!("{base_url}/EPG/jsp/getchannellistHWCTC.jsp").as_str())?;
    let response = client.get(url).send().await?.error_for_status()?;

    response.text().await.map_err(Into::into)
}

#[derive(Clone, Debug)]
pub(crate) struct Program {
    pub(crate) start: i64,
    pub(crate) stop: i64,
    pub(crate) title: String,
    pub(crate) desc: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Channel {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) rtsp: String,
    pub(crate) igmp: Option<String>,
    pub(crate) fcc_server: Option<String>,
    pub(crate) epg: Vec<Program>,
    pub(crate) time_shift_url: Option<String>,
}

#[derive(Deserialize)]
struct AuthJson {
    epgurl: String,
}

#[derive(Deserialize)]
struct TokenJson {
    #[serde(rename = "EncryToken")]
    encry_token: String,
}

#[derive(Deserialize)]
struct PlaybillList {
    #[serde(rename = "playbillLites")]
    list: Vec<Bill>,
}

#[derive(Deserialize)]
struct Bill {
    name: String,
    #[serde(rename = "startTime")]
    start_time: i64,
    #[serde(rename = "endTime")]
    end_time: i64,
}

fn ctc_channel_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new("Authentication.CTCSetConfig\\('Channel','(.+?)'\\)")
            .expect("valid CTC channel regex")
    })
}

pub(crate) fn derive_fcc_server(fields: &HashMap<String, String>, rtsp: &str) -> Option<String> {
    let default_port = fields
        .get("ChannelFCCPort")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && *p != "0")
        .unwrap_or("8027");

    if let Some(server) = fields
        .get("FCCServer")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "0.0.0.0")
    {
        if server.contains(':') {
            return Some(server.to_string());
        }
        return Some(format!("{server}:{default_port}"));
    }

    if let Some(ip) = fields
        .get("ChannelFCCIP")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "0.0.0.0")
    {
        if ip.contains(':') {
            return Some(ip.to_string());
        }
        return Some(format!("{ip}:{default_port}"));
    }

    Url::parse(rtsp)
        .ok()
        .and_then(|url| url.host_str().map(|host| format!("{host}:{default_port}")))
}

pub(crate) fn parse_channels_from_ctc(raw: &str) -> Vec<Channel> {
    let re = ctc_channel_regex();
    re.captures_iter(raw)
        .map(|cap| {
            cap[1]
                .split("\",")
                .filter_map(|pair| {
                    let (k, v) = pair.split_once("=\"")?;
                    Some((k.to_string(), v.trim_end_matches('"').to_string()))
                })
                .collect::<HashMap<_, _>>()
        })
        .filter_map(|m| {
            let id = m.get("ChannelID")?.parse::<u64>().ok()?;
            let name = m.get("ChannelName")?.clone();
            let channel_url = m.get("ChannelURL")?;
            let raw_rtsp = channel_url.split('|').find(|u| u.starts_with("rtsp"))?;
            let raw_igmp = channel_url
                .split('|')
                .find(|u| u.starts_with("igmp"))
                .map(str::to_owned);
            let fcc_server = derive_fcc_server(&m, raw_rtsp);
            if let Some(fcc_addr) = fcc_server.as_ref() {
                debug!("Channel {id} ({name}) derived FCC endpoint {fcc_addr}");
            }
            let rtsp = raw_rtsp.replace("zoneoffset=0", "zoneoffset=480");
            let time_shift_url = m.get("TimeShiftURL").cloned();
            Some(Channel {
                id,
                name,
                rtsp,
                igmp: raw_igmp,
                fcc_server,
                epg: Vec::new(),
                time_shift_url,
            })
        })
        .collect()
}

pub(crate) async fn get_channels(
    upstream_auth: &UpstreamAuthManager,
    creds: &UpstreamCredentials,
    interface: Option<&str>,
    need_epg: bool,
) -> Result<Vec<Channel>> {
    info!("Obtaining channels");

    let (client, base_url) = upstream_auth.resolve_session(creds, interface).await?;
    let res = match fetch_channellist_raw(&client, creds, &base_url).await {
        Ok(res) => res,
        Err(error) => {
            upstream_auth.invalidate_endpoint();
            return Err(error);
        }
    };
    upstream_auth.mark_success();

    let channels = parse_channels_from_ctc(&res);
    info!("Got {} channel(s)", channels.len());

    if !need_epg {
        return Ok(channels);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    // Cap concurrent EPG requests so a few hundred channels don't open a few
    // hundred simultaneous connections to the operator's EPG endpoint (which
    // tends to throttle or drop them).
    let epg_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(12));
    let mut tasks = JoinSet::new();

    for channel in channels.into_iter() {
        let params = [
            ("channelId", format!("{}", channel.id)),
            ("begin", format!("{}", now - 86400000 * 2)),
            ("end", format!("{}", now + 86400000 * 5)),
        ];
        let url = Url::parse_with_params(
            format!("{base_url}/EPG/jsp/iptvsnmv3/en/play/ajax/_ajax_getPlaybillList.jsp").as_str(),
            params,
        )?;
        let client = client.clone();
        let epg_limit = epg_limit.clone();
        tasks.spawn(async move {
            let _permit = epg_limit.acquire_owned().await;
            (client.get(url).send().await, channel)
        });
    }

    let mut channels = Vec::new();
    // Collect every channel regardless of per-channel EPG failures. A single
    // failed request must not truncate the whole list (which would drop the
    // remaining channels from the playlist/XMLTV entirely).
    while let Some(joined) = tasks.join_next().await {
        let (res, mut channel) = match joined {
            Ok(pair) => pair,
            Err(e) => {
                warn!("EPG task join error: {}", e);
                continue;
            }
        };
        match res {
            Ok(res) => {
                if let Ok(play_bill_list) = res.json::<PlaybillList>().await {
                    for bill in play_bill_list.list.into_iter() {
                        channel.epg.push(Program {
                            start: bill.start_time,
                            stop: bill.end_time,
                            title: bill.name.clone(),
                            desc: bill.name,
                        });
                    }
                }
            }
            Err(e) => warn!("EPG fetch failed for channel {}: {}", channel.id, e),
        }
        channels.push(channel);
    }

    channels.sort_by_key(|channel| channel.id);
    Ok(channels)
}

pub(crate) async fn get_channel_list_raw(
    upstream_auth: &UpstreamAuthManager,
    creds: &UpstreamCredentials,
    interface: Option<&str>,
) -> Result<String> {
    let (client, base_url) = upstream_auth.resolve_session(creds, interface).await?;
    match fetch_channellist_raw(&client, creds, &base_url).await {
        Ok(raw) => {
            upstream_auth.mark_success();
            Ok(raw)
        }
        Err(error) => {
            upstream_auth.invalidate_endpoint();
            Err(error)
        }
    }
}

pub(crate) async fn get_icon(
    upstream_auth: &UpstreamAuthManager,
    creds: &UpstreamCredentials,
    interface: Option<&str>,
    id: &str,
) -> Result<Vec<u8>> {
    let (client, base_url) = upstream_auth.resolve_session(creds, interface).await?;
    let url = Url::parse(&format!(
        "{base_url}/EPG/jsp/iptvsnmv3/en/list/images/channelIcon/{id}.png"
    ))?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(error) => {
            upstream_auth.invalidate_endpoint();
            return Err(error.into());
        }
    };
    if let Err(error) = response.error_for_status_ref() {
        if response.status() != StatusCode::NOT_FOUND {
            upstream_auth.invalidate_endpoint();
        }
        return Err(error.into());
    }
    Ok(response.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_ctc_urls_and_derives_fcc_server() {
        let sample = concat!(
            "Authentication.CTCSetConfig('Channel','ChannelID=\"101\",ChannelName=\"CCTV1高清\",",
            "ChannelURL=\"igmp://239.77.0.1:5146|rtsp://183.59.1.10:554/PLTV/1?zoneoffset=0\",",
            "ChannelFCCIP=\"183.59.2.20\",ChannelFCCPort=\"15970\",",
            "TimeShiftURL=\"rtsp://183.59.1.10:554/PLTV/1/shift?utc=1\"');\n",
            "Authentication.CTCSetConfig('Channel','ChannelID=\"102\",ChannelName=\"CCTV2\",",
            "ChannelURL=\"igmp://239.77.0.2:5146|rtsp://183.59.1.11:554/PLTV/2\"');",
        );

        let channels = parse_channels_from_ctc(sample);
        assert_eq!(channels.len(), 2);

        assert_eq!(channels[0].id, 101);
        assert_eq!(
            channels[0].rtsp,
            "rtsp://183.59.1.10:554/PLTV/1?zoneoffset=480"
        );
        assert_eq!(channels[0].igmp.as_deref(), Some("igmp://239.77.0.1:5146"));
        assert_eq!(channels[0].fcc_server.as_deref(), Some("183.59.2.20:15970"));
        assert_eq!(
            channels[0].time_shift_url.as_deref(),
            Some("rtsp://183.59.1.10:554/PLTV/1/shift?utc=1")
        );

        assert_eq!(channels[1].id, 102);
        assert_eq!(channels[1].fcc_server.as_deref(), Some("183.59.1.11:8027"));
    }
}
