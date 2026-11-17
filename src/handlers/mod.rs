mod manage;
pub(crate) mod media;
pub(crate) mod views;

pub(super) use manage::{
    manage_channels, manage_channels_html, manage_channels_raw, manage_config, manage_index,
    manage_reload, manage_test, status,
};
pub(super) use media::{logo, playlist_handler, rtp, rtsp, udp, xmltv};
