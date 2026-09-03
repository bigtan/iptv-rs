use crate::iptv::Channel;
use anyhow::{Result, anyhow};
use chrono::{FixedOffset, TimeZone, Utc};
use std::io::{BufWriter, Cursor};
use xml::{
    EventReader,
    reader::XmlEvent as XmlReadEvent,
    writer::{EmitterConfig, XmlEvent as XmlWriteEvent},
};

pub(crate) fn format_time(unix_time: i64) -> Result<String> {
    match Utc.timestamp_millis_opt(unix_time) {
        chrono::LocalResult::Single(time) => Ok(time
            .with_timezone(&FixedOffset::east_opt(8 * 60 * 60).ok_or(anyhow!(""))?)
            .format("%Y%m%d%H%M%S")
            .to_string()),
        _ => Err(anyhow!("fail to parse time")),
    }
}

pub(crate) fn render(
    channels: Vec<Channel>,
    extra: Vec<EventReader<Cursor<String>>>,
) -> Result<String> {
    let mut buf = BufWriter::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut buf);
    writer.write(
        XmlWriteEvent::start_element("tv")
            .attr("generator-info-name", "iptv-proxy")
            .attr("source-info-name", "iptv-proxy"),
    )?;
    for channel in &channels {
        writer
            .write(XmlWriteEvent::start_element("channel").attr("id", &channel.id.to_string()))?;
        writer.write(XmlWriteEvent::start_element("display-name"))?;
        writer.write(XmlWriteEvent::characters(&channel.name))?;
        writer.write(XmlWriteEvent::end_element())?;
        writer.write(XmlWriteEvent::end_element())?;
    }
    for reader in extra {
        for event in reader {
            match event {
                Ok(XmlReadEvent::StartElement {
                    name, attributes, ..
                }) => {
                    let name = name.to_string();
                    let name = name.as_str();
                    if !is_supported_element(name) {
                        continue;
                    }
                    let name = if name == "title"
                        && attributes.iter().any(|attribute| {
                            attribute.name.to_string() == "lang" && attribute.value != "chi"
                        }) {
                        "title_extra"
                    } else {
                        name
                    };
                    let mut tag = XmlWriteEvent::start_element(name);
                    for attribute in &attributes {
                        tag = tag.attr(attribute.name.borrow(), &attribute.value);
                    }
                    writer.write(tag)?;
                }
                Ok(XmlReadEvent::Characters(content)) => {
                    writer.write(XmlWriteEvent::characters(&content))?;
                }
                Ok(XmlReadEvent::EndElement { name })
                    if is_supported_element(&name.to_string()) =>
                {
                    writer.write(XmlWriteEvent::end_element())?;
                }
                _ => {}
            }
        }
    }
    for channel in &channels {
        for epg in &channel.epg {
            writer.write(
                XmlWriteEvent::start_element("programme")
                    .attr("start", &format!("{} +0800", format_time(epg.start)?))
                    .attr("stop", &format!("{} +0800", format_time(epg.stop)?))
                    .attr("channel", &channel.id.to_string()),
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

fn is_supported_element(name: &str) -> bool {
    matches!(
        name,
        "channel" | "display-name" | "desc" | "title" | "sub-title" | "programme"
    )
}
