use anyhow::Result;
use handlebars::Handlebars;
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) app: AppConfig,
    pub(crate) fcc: FccConfig,
    pub(crate) alias: AliasConfig,
    pub(crate) resolution: ResolutionConfig,
    pub(crate) groups: GroupConfig,
    pub(crate) sorting: SortingConfig,
    pub(crate) template: TemplateConfig,
    pub(crate) auth: AuthConfig,
    pub(crate) manage: ManageConfig,
    pub(crate) xmltv: XmltvConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AppConfig {
    pub(crate) user: Option<String>,
    pub(crate) passwd: Option<String>,
    pub(crate) mac: Option<String>,
    pub(crate) imei: Option<String>,
    pub(crate) bind: Option<String>,
    pub(crate) bind_interface: Option<String>,
    pub(crate) workers: Option<usize>,
    pub(crate) address: Option<String>,
    pub(crate) interface: Option<String>,
    pub(crate) rtsp_proxy: bool,
    pub(crate) udp_proxy: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FccConfig {
    pub(crate) enabled: bool,
    pub(crate) max_redirects: usize,
    pub(crate) switch_extra_packets: usize,
    pub(crate) switch_min_unicast_ms: u64,
}

impl Default for FccConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_redirects: 5,
            switch_extra_packets: 64,
            switch_min_unicast_ms: 500,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AliasConfig {
    pub(crate) mode: AliasMode,
    pub(crate) rules: Vec<AliasRule>,
}

impl Default for AliasConfig {
    fn default() -> Self {
        Self {
            mode: AliasMode::FirstMatch,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AliasMode {
    FirstMatch,
    Chain,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AliasRuleType {
    Map,
    Regex,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AliasRule {
    #[serde(rename = "type")]
    pub(crate) kind: AliasRuleType,
    pub(crate) pattern: String,
    pub(crate) replace: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResolutionConfig {
    pub(crate) default_score: i32,
    pub(crate) rules: Vec<ResolutionRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolutionRule {
    pub(crate) pattern: String,
    pub(crate) score: i32,
    pub(crate) label: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct GroupConfig {
    pub(crate) default_group: String,
    pub(crate) entries: Vec<GroupEntry>,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            default_group: String::from("未分组"),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupEntry {
    pub(crate) group: String,
    pub(crate) channels: Option<Vec<String>>,
    pub(crate) match_regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct SortingConfig {
    pub(crate) same_alias: Vec<String>,
    pub(crate) prefer_resolution: PreferResolutionConfig,
}

impl Default for SortingConfig {
    fn default() -> Self {
        Self {
            same_alias: vec![
                String::from("resolution_desc"),
                String::from("prefer_resolution"),
                String::from("original"),
            ],
            prefer_resolution: PreferResolutionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PreferResolutionConfig {
    pub(crate) order: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TemplateConfig {
    pub(crate) extinf: String,
    pub(crate) url: String,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            extinf: String::from(
                r#"#EXTINF:-1 tvg-id="{{tvg_id}}" tvg-name="{{alias_name}}" tvg-chno="{{tvg_chno}}"{{catchup_attr}}tvg-logo="{{tvg_logo}}" group-title="{{group}}",{{alias_name}}"#,
            ),
            url: String::from("{{url}}"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AuthConfig {
    pub(crate) token: String,
    pub(crate) protect: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            protect: vec![
                String::from("playlist"),
                String::from("xmltv"),
                String::from("manage"),
                String::from("rtsp"),
                String::from("udp"),
                String::from("logo"),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ManageConfig {
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct XmltvConfig {
    pub(crate) use_alias_name: bool,
}

impl Default for XmltvConfig {
    fn default() -> Self {
        Self {
            use_alias_name: true,
        }
    }
}

pub(crate) struct CompiledConfig {
    pub(crate) alias_rules: Vec<CompiledAliasRule>,
    pub(crate) resolution_rules: Vec<CompiledResolutionRule>,
    pub(crate) group_entries: Vec<CompiledGroupEntry>,
}

pub(crate) struct CompiledAliasRule {
    pub(crate) kind: AliasRuleType,
    pub(crate) pattern: String,
    pub(crate) regex: Option<Regex>,
    pub(crate) replace: String,
}

pub(crate) struct CompiledResolutionRule {
    pub(crate) regex: Regex,
    pub(crate) score: i32,
    pub(crate) label: Option<String>,
}

pub(crate) struct CompiledGroupEntry {
    pub(crate) group: String,
    pub(crate) channels: Option<Vec<String>>,
    pub(crate) regex: Option<Regex>,
}

pub(crate) fn load_config(path: Option<&str>) -> Result<Config> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub(crate) fn compile_config(config: &Config) -> Result<CompiledConfig> {
    let mut alias_rules = Vec::new();
    for rule in config.alias.rules.iter() {
        let regex = match rule.kind {
            AliasRuleType::Regex => Some(Regex::new(&rule.pattern)?),
            AliasRuleType::Map => None,
        };
        alias_rules.push(CompiledAliasRule {
            kind: rule.kind.clone(),
            pattern: rule.pattern.clone(),
            regex,
            replace: rule.replace.clone(),
        });
    }

    let mut resolution_rules = Vec::new();
    for rule in config.resolution.rules.iter() {
        resolution_rules.push(CompiledResolutionRule {
            regex: Regex::new(&rule.pattern)?,
            score: rule.score,
            label: rule.label.clone(),
        });
    }

    let mut group_entries = Vec::new();
    for entry in config.groups.entries.iter() {
        let regex = if let Some(pattern) = entry.match_regex.as_ref() {
            Some(Regex::new(pattern)?)
        } else {
            None
        };
        group_entries.push(CompiledGroupEntry {
            group: entry.group.clone(),
            channels: entry.channels.clone(),
            regex,
        });
    }

    Ok(CompiledConfig {
        alias_rules,
        resolution_rules,
        group_entries,
    })
}

pub(crate) fn build_templates(config: &Config) -> Result<Handlebars<'static>> {
    let mut hb = Handlebars::new();
    hb.register_escape_fn(handlebars::no_escape);
    hb.set_strict_mode(false);
    hb.register_template_string("extinf", config.template.extinf.clone())?;
    hb.register_template_string("url", config.template.url.clone())?;
    Ok(hb)
}

pub(crate) fn should_protect(config: &Config, endpoint: &str) -> bool {
    config
        .auth
        .protect
        .iter()
        .any(|e| e.eq_ignore_ascii_case(endpoint))
}

pub(crate) fn redacted(config: &Config) -> Config {
    let mut safe = config.clone();
    for value in [
        &mut safe.app.user,
        &mut safe.app.passwd,
        &mut safe.app.mac,
        &mut safe.app.imei,
    ] {
        if value.is_some() {
            *value = Some("REDACTED".to_string());
        }
    }
    if !safe.auth.token.is_empty() {
        safe.auth.token = "REDACTED".to_string();
    }
    safe
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ManageTestResult {
    pub(crate) input: String,
    pub(crate) alias_name: String,
    pub(crate) resolution_score: i32,
    pub(crate) resolution_label: String,
    pub(crate) group: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_configuration_fields() {
        let error = toml::from_str::<Config>(
            r#"
                [app]
                user = "user"
                unexpected = true
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unexpected"));
    }

    #[test]
    fn parses_new_listener_fields_and_rejects_removed_source_priority() {
        let parsed = toml::from_str::<Config>(
            r#"
                [app]
                bind = "[::]:7088"
                bind_interface = "br-lan"
                workers = 2
                udp_proxy = true
            "#,
        )
        .expect("listener fields should parse");
        assert_eq!(parsed.app.bind_interface.as_deref(), Some("br-lan"));
        assert_eq!(parsed.app.workers, Some(2));
        assert!(parsed.app.udp_proxy);

        let removed = toml::from_str::<Config>(
            r#"
                [sorting]
                source_priority = ["gd-iptv"]
            "#,
        )
        .unwrap_err();
        assert!(removed.to_string().contains("source_priority"));
    }

    #[test]
    fn default_auth_protects_all_sensitive_endpoints() {
        let auth = AuthConfig::default();
        assert!(auth.token.is_empty());
        assert_eq!(
            auth.protect,
            vec!["playlist", "xmltv", "manage", "rtsp", "udp", "logo"]
        );
    }

    #[test]
    fn redacts_every_upstream_identity_field() {
        let mut config = Config::default();
        config.app.user = Some("user".to_string());
        config.app.passwd = Some("password".to_string());
        config.app.mac = Some("mac".to_string());
        config.app.imei = Some("imei".to_string());
        config.auth.token = "token".to_string();

        let safe = redacted(&config);
        assert_eq!(safe.app.user.as_deref(), Some("REDACTED"));
        assert_eq!(safe.app.passwd.as_deref(), Some("REDACTED"));
        assert_eq!(safe.app.mac.as_deref(), Some("REDACTED"));
        assert_eq!(safe.app.imei.as_deref(), Some("REDACTED"));
        assert_eq!(safe.auth.token, "REDACTED");
    }

    #[test]
    fn shipped_config_file_parses_and_compiles_cleanly() {
        let raw = include_str!("../config/iptv.toml");
        assert!(toml::from_str::<Config>(raw).is_ok());
        let config: Config = toml::from_str(raw).expect("config/iptv.toml must parse cleanly");
        compile_config(&config).expect("config/iptv.toml regexes must compile");
        build_templates(&config).expect("config/iptv.toml templates must compile");
    }

    #[cfg(unix)]
    #[test]
    fn openwrt_init_rendered_toml_parses_against_config() {
        let out_path =
            std::env::temp_dir().join(format!("iptv-openwrt-init-{}.toml", rand::random::<u64>()));
        let script = r#"
            set -eu
            eval "$(sed '1d' openwrt/iptv/files/iptv.init)"
            TOML_CONFIG="$1"
            config_get() {
                local var="$1" sec="$2" opt="$3" def="${4:-}"
                case "$sec:$opt" in
                    main:bind) eval "$var='[::]:7088'" ;;
                    main:bind_interface) eval "$var='br-lan'" ;;
                    main:workers) eval "$var='2'" ;;
                    main:interface) eval "$var='pppoe-iptv'" ;;
                    main:alias_mode) eval "$var='first_match'" ;;
                    main:default_group) eval "$var='未分组'" ;;
                    main:fcc_max_redirects) eval "$var='5'" ;;
                    main:fcc_switch_extra_packets) eval "$var='64'" ;;
                    main:fcc_switch_min_unicast_ms) eval "$var='500'" ;;
                    r1:type) eval "$var='regex'" ;;
                    r1:pattern) eval "$var='^CCTV1$'" ;;
                    r1:replace) eval "$var='CCTV-1'" ;;
                    res1:pattern) eval "$var='(?i)4k'" ;;
                    res1:score) eval "$var='400'" ;;
                    res1:label) eval "$var='R4K'" ;;
                    g1:group) eval "$var='#IPTV-央视'" ;;
                    g1:match_regex) eval "$var=''" ;;
                    *) eval "$var=\"\$def\"" ;;
                esac
            }
            config_get_bool() {
                local var="$1" sec="$2" opt="$3" def="${4:-0}"
                case "$sec:$opt" in
                    main:udp_proxy|main:rtsp_proxy|main:manage_enabled|main:xmltv_use_alias_name) eval "$var='1'" ;;
                    main:fcc_enabled) eval "$var='0'" ;;
                    *) eval "$var=\"\$def\"" ;;
                esac
            }
            config_list_foreach() {
                local sec="$1" opt="$2" cb="$3"
                case "$sec:$opt" in
                    main:auth_protect)
                        for item in playlist xmltv manage rtsp udp logo; do "$cb" "$item"; done ;;
                    main:same_alias)
                        for item in resolution_desc prefer_resolution original; do "$cb" "$item"; done ;;
                    main:prefer_resolution)
                        for item in R4K Uhd Fhd Hd Sd Unknown; do "$cb" "$item"; done ;;
                    g1:channels)
                        for item in CCTV1 CCTV2; do "$cb" "$item"; done ;;
                esac
            }
            config_foreach() {
                local cb="$1" kind="$2"
                case "$kind" in
                    alias_rule) "$cb" r1 ;;
                    resolution_rule) "$cb" res1 ;;
                    group) "$cb" g1 ;;
                esac
            }
            generate_toml
        "#;

        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("sh")
            .arg(&out_path)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("sh should execute");
        assert!(status.success(), "generate_toml should exit cleanly");

        let rendered = std::fs::read_to_string(&out_path).expect("rendered TOML should exist");
        let _ = std::fs::remove_file(&out_path);

        let parsed: Config =
            toml::from_str(&rendered).expect("OpenWrt generated TOML must match Config schema");
        assert_eq!(parsed.app.bind_interface.as_deref(), Some("br-lan"));
        assert_eq!(parsed.app.workers, Some(2));
        assert!(parsed.app.udp_proxy);
        assert!(parsed.app.rtsp_proxy);
        compile_config(&parsed).expect("OpenWrt generated TOML rules must compile");
    }
}
