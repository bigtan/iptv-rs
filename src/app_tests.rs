use super::*;
use crate::handlers::media::is_valid_logo_id;
use crate::handlers::views::{is_safe_stream_url, render_channels};
use crate::xmltv_output::render as to_xmltv;
use actix_web::{App, http::StatusCode, test as actix_test};

fn cli_args() -> Args {
    Args {
        user: None,
        passwd: None,
        mac: None,
        imei: None,
        bind: None,
        bind_interface: None,
        workers: None,
        address: None,
        interface: None,
        config: None,
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

fn build_test_state(args: Args, config: Config, config_path: Option<String>) -> Data<AppState> {
    let compiled = compile_config(&config).unwrap();
    let templates = build_templates(&config).unwrap();
    let effective_args = build_effective_args(&args, &config).unwrap();
    Data::new(AppState {
        cli_args: args,
        config_path,
        shared_proxy: SharedProxyRegistry::new(),
        caches: CacheStore::new(),
        upstream_auth: Arc::new(UpstreamAuthManager::default()),
        runtime: RwLock::new(Arc::new(RuntimeConfig {
            config,
            compiled,
            templates,
            effective_args,
        })),
    })
}

#[test]
fn effective_args_apply_cli_precedence_and_listener_options() {
    let mut args = cli_args();
    args.user = Some("cli-user".to_string());
    args.bind_interface = Some("br-lan".to_string());
    args.workers = Some(2);
    args.udp_proxy = true;
    let mut config = configured_app();
    config.app.bind_interface = Some("eth0".to_string());
    config.app.workers = Some(4);

    let effective = build_effective_args(&args, &config).unwrap();
    let creds = effective.upstream.expect("credentials should be present");

    assert_eq!(creds.user, "cli-user");
    assert_eq!(creds.passwd, "config-pass");
    assert_eq!(effective.interface.as_deref(), Some("iptv0"));
    assert_eq!(effective.bind_interface.as_deref(), Some("br-lan"));
    assert_eq!(effective.workers, Some(2));
    assert!(effective.udp_proxy);
}

#[test]
fn proxy_only_mode_and_partial_credentials_validation() {
    // Standalone proxy-only mode succeeds when all credentials are omitted/empty
    // and at least one of udp_proxy / rtsp_proxy is enabled.
    let mut proxy_cfg = Config::default();
    proxy_cfg.app.udp_proxy = true;
    proxy_cfg.app.user = Some("   ".to_string());
    let effective = build_effective_args(&cli_args(), &proxy_cfg).unwrap();
    assert!(effective.upstream.is_none());
    assert!(effective.udp_proxy);

    // Neither credentials nor any proxy enabled must error clearly.
    let err = build_effective_args(&cli_args(), &Config::default()).unwrap_err();
    assert!(err.to_string().contains("udp_proxy"));

    // Partially specified credentials must error even when udp_proxy is enabled.
    let mut partial = Config::default();
    partial.app.udp_proxy = true;
    partial.app.user = Some("only-user".to_string());
    let err = build_effective_args(&cli_args(), &partial).unwrap_err();
    assert!(err.to_string().contains("Incomplete upstream credentials"));

    // workers = 0 must error.
    let mut zero_workers = proxy_cfg.clone();
    zero_workers.app.workers = Some(0);
    assert!(build_effective_args(&cli_args(), &zero_workers).is_err());
}

#[actix_web::test]
async fn proxy_only_endpoints_and_logo_id_validation() {
    let mut config = Config::default();
    config.app.udp_proxy = true;
    config.app.rtsp_proxy = true;
    config.manage.enabled = true;
    let state = build_test_state(cli_args(), config, None);

    let app = actix_test::init_service(
        App::new()
            .service(playlist_handler)
            .service(xmltv)
            .service(logo)
            .service(status)
            .service(manage_channels)
            .service(manage_channels_raw)
            .service(manage_channels_html)
            .app_data(state),
    )
    .await;

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri("/playlist").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = actix_test::read_body(resp).await;
    assert_eq!(&body[..], b"#EXTM3U\n");

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri("/xmltv").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap();
    assert_eq!(
        body,
        r#"<?xml version="1.0" encoding="UTF-8"?><tv generator-info-name="iptv-proxy" source-info-name="iptv-proxy"/>"#
    );

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/manage/channels")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&actix_test::read_body(resp).await[..], b"[]");

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/manage/channels/raw")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Valid logo ID in proxy-only mode returns 404 Not Found.
    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/logo/101.png")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Invalid logo IDs return 400 Bad Request.
    let too_long = format!("/logo/{}.png", "a".repeat(65));
    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri(&too_long).to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bad_chars = "/logo/bad$id.png";
    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri(bad_chars).to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    assert!(is_valid_logo_id("CCTV-1_HD"));
    assert!(is_valid_logo_id(&"x".repeat(64)));
    assert!(!is_valid_logo_id(""));
    assert!(!is_valid_logo_id("../etc"));
}

#[test]
fn build_local_entries_rewrites_per_host_and_protected_stream_urls_receive_token() {
    let mut config = configured_app();
    config.app.rtsp_proxy = true;
    config.app.udp_proxy = true;
    config.auth.token = "secret".to_string();
    // Default AuthConfig::default().protect covers playlist, xmltv, manage, rtsp, udp, logo.
    let args = build_effective_args(&cli_args(), &config).unwrap();

    let raw_channel = Channel {
        id: 1,
        name: "Channel".to_string(),
        rtsp: "rtsp://10.0.0.2:554/live".to_string(),
        igmp: Some("igmp://239.77.0.1:5146".to_string()),
        fcc_server: Some("10.0.0.2:8027".to_string()),
        epg: Vec::new(),
        time_shift_url: Some("rtsp://10.0.0.2:554/replay?utc=1".to_string()),
    };

    let entries_v4 = build_local_entries(
        vec![raw_channel.clone()],
        &args,
        "http",
        "192.168.1.1:7088",
        "seek",
        0,
        None,
    );
    assert_eq!(
        entries_v4[0].url,
        "http://192.168.1.1:7088/udp/239.77.0.1:5146?fcc=10.0.0.2:8027"
    );

    let mut entries_v6 = build_local_entries(
        vec![raw_channel],
        &args,
        "http",
        "[fd00::1]:7088",
        "seek",
        0,
        None,
    );
    assert_eq!(
        entries_v6[0].url,
        "http://[fd00::1]:7088/udp/239.77.0.1:5146?fcc=10.0.0.2:8027"
    );

    protect_local_entry_urls(&mut entries_v6, &config);
    assert!(entries_v6[0].url.contains("token=secret"));
    assert!(entries_v6[0].tvg_logo.contains("token=secret"));
    assert!(entries_v6[0].catchup_source.contains("token=secret"));
    assert!(entries_v6[0].catchup_source.ends_with("&playseek=seek"));

    // Upstream cache key depends solely on credentials + interface + epg flag.
    let creds = args.upstream.as_ref().unwrap();
    let k1 = upstream_cache_key(creds, args.interface.as_deref(), false);
    let k2 = upstream_cache_key(creds, args.interface.as_deref(), false);
    assert_eq!(k1, k2);
}

#[test]
fn views_render_channels_blocks_unsafe_schemes() {
    assert!(is_safe_stream_url(
        "http://192.168.1.1:7088/udp/239.0.0.1:5000"
    ));
    assert!(is_safe_stream_url("RTSP://10.0.0.1/live"));
    assert!(is_safe_stream_url("igmp://239.0.0.1:5000"));
    assert!(!is_safe_stream_url("javascript:alert(1)"));
    assert!(!is_safe_stream_url(
        "data:text/html,<script>alert(1)</script>"
    ));

    let unsafe_entry = ChannelEntry {
        key: "gd:1:0".to_string(),
        source: "gd-iptv".to_string(),
        channel_id: Some(1),
        url: "javascript:alert(1)".to_string(),
        raw_name: "Test".to_string(),
        alias_name: "Test".to_string(),
        group: "Default".to_string(),
        tvg_id: "1".to_string(),
        tvg_name: "Test".to_string(),
        tvg_logo: String::new(),
        tvg_chno: "1".to_string(),
        catchup: String::new(),
        catchup_source: String::new(),
        catchup_attr: String::new(),
        extras: BTreeMap::new(),
        resolution_score: 0,
        resolution_label: "Unknown".to_string(),
        original_index: 0,
    };
    let html = render_channels(&[unsafe_entry], None);
    assert!(html.contains("href='#'"));
    assert!(!html.contains("href='javascript:"));
}

#[actix_web::test]
async fn reload_updates_runtime_clears_caches_and_conflicts_on_listener_changes() {
    let path =
        std::env::temp_dir().join(format!("iptv-reload-test-{}.toml", rand::random::<u64>()));
    std::fs::write(
        &path,
        r#"
[app]
bind = "127.0.0.1:17088"
bind_interface = "br-lan"
workers = 2
udp_proxy = true

[manage]
enabled = true
"#,
    )
    .unwrap();

    let initial_cfg = load_config(path.to_str()).unwrap();
    let state = build_test_state(
        cli_args(),
        initial_cfg,
        Some(path.to_string_lossy().into_owned()),
    );
    let gen0 = state.caches.generation();
    state
        .caches
        .put_playlist(gen0, "k".to_string(), "cached".to_string());
    assert!(state.caches.get_playlist("k").is_some());

    // Reloading non-listener settings succeeds, bumps generation, and clears caches.
    std::fs::write(
        &path,
        r#"
[app]
bind = "127.0.0.1:17088"
bind_interface = "br-lan"
workers = 2
udp_proxy = true
rtsp_proxy = true

[manage]
enabled = true
"#,
    )
    .unwrap();
    reload_runtime_config(&state).expect("hot reload should succeed");
    assert!(state.runtime().effective_args.rtsp_proxy);
    assert_ne!(state.caches.generation(), gen0);
    assert!(state.caches.get_playlist("k").is_none());

    // Changing workers or bind_interface returns 409 Conflict via /manage/reload.
    std::fs::write(
        &path,
        r#"
[app]
bind = "127.0.0.1:17088"
bind_interface = "eth0"
workers = 2
udp_proxy = true

[manage]
enabled = true
"#,
    )
    .unwrap();

    let app = actix_test::init_service(App::new().service(manage_reload).app_data(state)).await;
    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/manage/reload")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn xmltv_generation_and_http_listener_binding_work() {
    let channel = Channel {
        id: 7,
        name: "News & Sports".to_string(),
        rtsp: String::new(),
        igmp: None,
        fcc_server: None,
        epg: Vec::new(),
        time_shift_url: None,
    };

    let document = to_xmltv(&[channel]).unwrap();
    assert!(document.contains("News &amp; Sports"));
    assert!(document.ends_with("</tv>"));

    let listener = bind_http_listener("127.0.0.1:0", None).unwrap();
    assert!(listener.local_addr().unwrap().port() > 0);
}
