use crate::iptv::Channel;
use anyhow::{Result, anyhow};
use chrono::{FixedOffset, TimeZone, Utc};
use std::borrow::Cow;

pub(crate) fn format_time(unix_time: i64) -> Result<String> {
    match Utc.timestamp_millis_opt(unix_time) {
        chrono::LocalResult::Single(time) => Ok(time
            .with_timezone(&FixedOffset::east_opt(8 * 60 * 60).ok_or(anyhow!("invalid offset"))?)
            .format("%Y%m%d%H%M%S")
            .to_string()),
        _ => Err(anyhow!("fail to parse time")),
    }
}

pub(crate) fn xml_escape(input: &str) -> Cow<'_, str> {
    if !input
        .bytes()
        .any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\''))
    {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len() + 16);
    push_xml_escaped(&mut out, input);
    Cow::Owned(out)
}

fn push_xml_escaped(out: &mut String, input: &str) {
    let bytes = input.as_bytes();
    let mut last = 0;
    for (idx, &b) in bytes.iter().enumerate() {
        let replacement = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&apos;",
            _ => continue,
        };
        if last < idx {
            out.push_str(&input[last..idx]);
        }
        out.push_str(replacement);
        last = idx + 1;
    }
    if last < input.len() {
        out.push_str(&input[last..]);
    }
}

pub(crate) fn render(channels: &[Channel]) -> Result<String> {
    let estimated_bytes = 128
        + channels
            .iter()
            .map(|c| 96 + c.name.len() + c.epg.len().saturating_mul(192))
            .sum::<usize>();
    let mut out = String::with_capacity(estimated_bytes);
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    if channels.is_empty() {
        out.push_str(r#"<tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy"/>"#);
        return Ok(out);
    }

    out.push_str(r#"<tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy">"#);

    for channel in channels {
        out.push_str(r#"<channel id=""#);
        let id_str = channel.id.to_string();
        out.push_str(&xml_escape(&id_str));
        out.push_str(r#""><display-name>"#);
        out.push_str(&xml_escape(&channel.name));
        out.push_str("</display-name></channel>");
    }

    for channel in channels {
        let id_str = channel.id.to_string();
        for epg in &channel.epg {
            let start = format_time(epg.start)?;
            let stop = format_time(epg.stop)?;
            out.push_str(r#"<programme start=""#);
            out.push_str(&xml_escape(&start));
            out.push_str(r#" +0800" stop=""#);
            out.push_str(&xml_escape(&stop));
            out.push_str(r#" +0800" channel=""#);
            out.push_str(&xml_escape(&id_str));
            out.push_str(r#""><title lang="chi">"#);
            out.push_str(&xml_escape(&epg.title));
            out.push_str("</title>");
            if !epg.desc.is_empty() {
                out.push_str("<desc>");
                out.push_str(&xml_escape(&epg.desc));
                out.push_str("</desc>");
            }
            out.push_str("</programme>");
        }
    }

    out.push_str("</tv>");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iptv::Program;

    #[test]
    fn xml_escape_handles_all_five_special_characters() {
        assert_eq!(
            xml_escape(r#"News & <Sports> "HD" 'Live'"#),
            "News &amp; &lt;Sports&gt; &quot;HD&quot; &apos;Live&apos;"
        );
        assert!(matches!(xml_escape("Plain CCTV1"), Cow::Borrowed(_)));
    }

    #[test]
    fn render_empty_channels_emits_valid_self_closing_tv() {
        let xml = render(&[]).unwrap();
        assert_eq!(
            xml,
            r#"<?xml version="1.0" encoding="UTF-8"?><tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy"/>"#
        );
    }

    #[test]
    fn render_places_all_channels_before_programmes_and_escapes_content() {
        let channels = vec![
            Channel {
                id: 1,
                name: "CCTV 1 & <HD>".to_string(),
                rtsp: String::new(),
                igmp: None,
                fcc_server: None,
                epg: vec![Program {
                    start: 1_700_000_000_000,
                    stop: 1_700_003_600_000,
                    title: r#"Morning "News" & 'Report'"#.to_string(),
                    desc: "A < B > C & D".to_string(),
                }],
                time_shift_url: None,
            },
            Channel {
                id: 2,
                name: "Sports '4K' \"Live\"".to_string(),
                rtsp: String::new(),
                igmp: None,
                fcc_server: None,
                epg: vec![Program {
                    start: 1_700_003_600_000,
                    stop: 1_700_007_200_000,
                    title: "Match".to_string(),
                    desc: String::new(),
                }],
                time_shift_url: None,
            },
        ];

        let xml = render(&channels).unwrap();
        assert!(xml.starts_with(
            r#"<?xml version="1.0" encoding="UTF-8"?><tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy">"#
        ));
        assert!(xml.ends_with("</tv>"));

        let ch1_pos = xml.find(r#"<channel id="1">"#).unwrap();
        let ch2_pos = xml.find(r#"<channel id="2">"#).unwrap();
        let prog1_pos = xml.find(r#"channel="1""#).unwrap();
        let prog2_pos = xml.find(r#"channel="2""#).unwrap();
        assert!(ch1_pos < ch2_pos);
        assert!(ch2_pos < prog1_pos);
        assert!(prog1_pos < prog2_pos);

        assert!(xml.contains("<display-name>CCTV 1 &amp; &lt;HD&gt;</display-name>"));
        assert!(
            xml.contains("<display-name>Sports &apos;4K&apos; &quot;Live&quot;</display-name>")
        );
        assert!(xml.contains(
            r#"<title lang="chi">Morning &quot;News&quot; &amp; &apos;Report&apos;</title>"#
        ));
        assert!(xml.contains("<desc>A &lt; B &gt; C &amp; D</desc>"));
        // Channel 2's programme has empty desc, so no second <desc> should be emitted.
        assert_eq!(xml.matches("<desc>").count(), 1);
    }
}
