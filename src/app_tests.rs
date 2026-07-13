use super::*;

fn cli_args() -> Args {
    Args {
        user: None,
        passwd: None,
        mac: None,
        imei: None,
        bind: None,
        address: None,
        interface: None,
        config: None,
        extra_playlist: Vec::new(),
        extra_xmltv: Vec::new(),
        udp_proxy: false,
        rtsp_proxy: false,
    }
}

fn configured_app() -> Config {
    let mut config = Config::default();
    config.app.user = Some("config-user".to_string());
    config.app.passwd = Some("config-pass".to_string());
    config.app.mac = Some("00:11:22:33:44:55".to_string());
    config.app.interface = Some("iptv0".to_string());
    config
}

#[test]
fn effective_args_apply_cli_precedence() {
    let mut args = cli_args();
    args.user = Some("cli-user".to_string());
    args.udp_proxy = true;
    let config = configured_app();

    let effective = build_effective_args(&args, &config).unwrap();

    assert_eq!(effective.user, "cli-user");
    assert_eq!(effective.passwd, "config-pass");
    assert_eq!(effective.interface.as_deref(), Some("iptv0"));
    assert!(effective.udp_proxy);
}

#[test]
fn output_cache_expires_entries() {
    let cache = Mutex::new(HashMap::new());
    put_cached_text(
        &cache,
        "key".to_string(),
        "value".to_string(),
        Duration::ZERO,
    );

    assert!(get_cached_text(&cache, "key").is_none());
    assert!(cache.lock().unwrap().is_empty());
}

#[test]
fn stale_cache_is_bounded() {
    let cache = Mutex::new(HashMap::new());
    for index in 0..=MAX_OUTPUT_CACHE_ENTRIES {
        put_stale_text(&cache, index.to_string(), "value".to_string());
    }

    assert_eq!(cache.lock().unwrap().len(), MAX_OUTPUT_CACHE_ENTRIES);
}

#[test]
fn protected_stream_urls_receive_local_token() {
    let mut config = configured_app();
    config.auth.token = "secret".to_string();
    config.auth.protect = vec!["rtsp".to_string(), "logo".to_string()];
    let args = build_effective_args(&cli_args(), &config).unwrap();
    let channel = Channel {
        id: 1,
        name: "Channel".to_string(),
        rtsp: "http://proxy/rtsp/10.0.0.2/live".to_string(),
        igmp: None,
        epg: Vec::new(),
        time_shift_url: Some("http://proxy/rtsp/10.0.0.2/replay?utc=1".to_string()),
    };
    let mut entries = build_local_entries(vec![channel], &args, "http", "proxy", "seek", 0, None);

    protect_local_entry_urls(&mut entries, &config);

    assert!(entries[0].url.contains("token=secret"));
    assert!(entries[0].tvg_logo.contains("token=secret"));
    assert!(entries[0].catchup_source.contains("token=secret"));
    assert!(entries[0].catchup_source.contains("playseek=seek"));
}

#[test]
fn xmltv_generation_produces_parseable_document() {
    let channel = Channel {
        id: 7,
        name: "News & Sports".to_string(),
        rtsp: String::new(),
        igmp: None,
        epg: Vec::new(),
        time_shift_url: None,
    };

    let document = to_xmltv(vec![channel], Vec::new()).unwrap();
    let events = EventReader::new(Cursor::new(document))
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>();

    assert!(events.is_ok());
}
