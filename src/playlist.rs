use crate::config::{AliasMode, AliasRuleType, CompiledConfig, Config, SortingConfig};
use anyhow::Result;
use handlebars::Handlebars;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChannelEntry {
    pub(crate) key: String,
    pub(crate) source: String,
    pub(crate) channel_id: Option<u64>,
    pub(crate) url: String,
    pub(crate) raw_name: String,
    pub(crate) alias_name: String,
    pub(crate) group: String,
    pub(crate) tvg_id: String,
    pub(crate) tvg_name: String,
    pub(crate) tvg_logo: String,
    pub(crate) tvg_chno: String,
    pub(crate) catchup: String,
    pub(crate) catchup_source: String,
    pub(crate) catchup_attr: String,
    pub(crate) extras: BTreeMap<String, String>,
    pub(crate) resolution_score: i32,
    pub(crate) resolution_label: String,
    pub(crate) original_index: usize,
}

pub(crate) struct EntryBuildContext<'a> {
    pub(crate) config: &'a Config,
    pub(crate) compiled: &'a CompiledConfig,
}

pub(crate) fn apply_alias(name: &str, config: &Config, compiled: &CompiledConfig) -> String {
    let mut current = name.to_string();
    match config.alias.mode {
        AliasMode::FirstMatch => {
            for rule in compiled.alias_rules.iter() {
                match rule.kind {
                    AliasRuleType::Map => {
                        if current == rule.pattern {
                            return rule.replace.clone();
                        }
                    }
                    AliasRuleType::Regex => {
                        if let Some(re) = rule.regex.as_ref()
                            && re.is_match(&current)
                        {
                            return re.replace_all(&current, rule.replace.as_str()).to_string();
                        }
                    }
                }
            }
            current
        }
        AliasMode::Chain => {
            for rule in compiled.alias_rules.iter() {
                match rule.kind {
                    AliasRuleType::Map => {
                        if current == rule.pattern {
                            current = rule.replace.clone();
                        }
                    }
                    AliasRuleType::Regex => {
                        if let Some(re) = rule.regex.as_ref()
                            && re.is_match(&current)
                        {
                            current = re.replace_all(&current, rule.replace.as_str()).to_string();
                        }
                    }
                }
            }
            current
        }
    }
}

pub(crate) fn infer_resolution(
    raw: &str,
    config: &Config,
    compiled: &CompiledConfig,
) -> (i32, String) {
    for rule in compiled.resolution_rules.iter() {
        if rule.regex.is_match(raw) {
            return (
                rule.score,
                rule.label.clone().unwrap_or_else(|| "Unknown".to_string()),
            );
        }
    }
    (config.resolution.default_score, "Unknown".to_string())
}

pub(crate) fn finalize_entries(
    mut entries: Vec<ChannelEntry>,
    ctx: &EntryBuildContext,
) -> Vec<ChannelEntry> {
    for entry in entries.iter_mut() {
        let alias = apply_alias(&entry.raw_name, ctx.config, ctx.compiled);
        let alias = alias.trim().to_string();
        entry.alias_name = if alias.is_empty() {
            entry.raw_name.clone()
        } else {
            alias
        };
        if entry.tvg_name.is_empty() {
            entry.tvg_name = entry.alias_name.clone();
        }
        if entry.tvg_id.is_empty() {
            entry.tvg_id = entry.alias_name.clone();
        }
        let (score, label) = infer_resolution(&entry.raw_name, ctx.config, ctx.compiled);
        entry.resolution_score = score;
        entry.resolution_label = label;
    }
    assign_groups(entries, ctx)
}

fn assign_groups(mut entries: Vec<ChannelEntry>, ctx: &EntryBuildContext) -> Vec<ChannelEntry> {
    if ctx.compiled.group_entries.is_empty() {
        for entry in entries.iter_mut() {
            if entry.group.is_empty() {
                entry.group = ctx.config.groups.default_group.clone();
            }
        }
        return entries;
    }

    let total = entries.len();
    let mut by_alias: HashMap<String, Vec<ChannelEntry>> = HashMap::with_capacity(total);
    for entry in entries {
        by_alias
            .entry(entry.alias_name.clone())
            .or_default()
            .push(entry);
    }

    let mut output = Vec::with_capacity(total);
    for group_entry in ctx.compiled.group_entries.iter() {
        if let Some(channels) = group_entry.channels.as_ref() {
            for name in channels.iter() {
                if let Some(mut picked) = by_alias.remove(name.as_str()) {
                    for entry in picked.iter_mut() {
                        entry.group = group_entry.group.clone();
                    }
                    sort_same_alias(&mut picked, &ctx.config.sorting);
                    output.extend(picked);
                }
            }
        } else if let Some(regex) = group_entry.regex.as_ref() {
            let matched_keys: Vec<String> = by_alias
                .keys()
                .filter(|alias| regex.is_match(alias))
                .cloned()
                .collect();
            let mut picked = Vec::new();
            for key in matched_keys {
                if let Some(mut bucket) = by_alias.remove(&key) {
                    for entry in bucket.iter_mut() {
                        entry.group = group_entry.group.clone();
                    }
                    picked.append(&mut bucket);
                }
            }
            sort_by_alias_then_resolution(&mut picked, &ctx.config.sorting);
            output.extend(picked);
        }
    }

    let mut remaining = Vec::with_capacity(total.saturating_sub(output.len()));
    for mut bucket in by_alias.into_values() {
        for entry in bucket.iter_mut() {
            entry.group = ctx.config.groups.default_group.clone();
        }
        remaining.append(&mut bucket);
    }
    sort_by_alias_then_resolution(&mut remaining, &ctx.config.sorting);
    output.extend(remaining);
    output
}

fn sort_by_alias_then_resolution(entries: &mut [ChannelEntry], sorting: &SortingConfig) {
    entries.sort_by(|a, b| {
        let name_cmp = a.alias_name.cmp(&b.alias_name);
        if name_cmp != std::cmp::Ordering::Equal {
            return name_cmp;
        }
        compare_same_alias(a, b, sorting)
    });
}

fn sort_same_alias(entries: &mut [ChannelEntry], sorting: &SortingConfig) {
    entries.sort_by(|a, b| compare_same_alias(a, b, sorting));
}

fn compare_same_alias(
    a: &ChannelEntry,
    b: &ChannelEntry,
    sorting: &SortingConfig,
) -> std::cmp::Ordering {
    for rule in sorting.same_alias.iter() {
        match rule.as_str() {
            "prefer_resolution" => {
                let rank_a = resolution_rank(&a.resolution_label, &sorting.prefer_resolution.order);
                let rank_b = resolution_rank(&b.resolution_label, &sorting.prefer_resolution.order);
                let cmp = rank_a.cmp(&rank_b);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            "resolution_desc" => {
                let cmp = b.resolution_score.cmp(&a.resolution_score);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            "original" => {
                let cmp = a.original_index.cmp(&b.original_index);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            _ => {}
        }
    }
    std::cmp::Ordering::Equal
}

fn resolution_rank(label: &str, order: &[String]) -> usize {
    order
        .iter()
        .position(|v| v.eq_ignore_ascii_case(label))
        .unwrap_or(order.len())
}

pub(crate) fn render_playlist(
    entries: &[ChannelEntry],
    hb: &Handlebars<'static>,
) -> Result<String> {
    if entries.is_empty() {
        return Ok(String::from("#EXTM3U\n"));
    }
    let mut out = String::with_capacity(entries.len().saturating_mul(160) + 16);
    out.push_str("#EXTM3U\n");
    for entry in entries.iter() {
        let extinf = hb.render("extinf", entry)?;
        let url = hb.render("url", entry)?;
        out.push_str(&extinf);
        out.push('\n');
        out.push_str(&url);
        out.push('\n');
    }
    Ok(out)
}

pub(crate) fn add_alias_and_resolution_for_name(
    name: &str,
    ctx: &EntryBuildContext,
) -> (String, i32, String) {
    let alias = apply_alias(name, ctx.config, ctx.compiled);
    let (score, label) = infer_resolution(name, ctx.config, ctx.compiled);
    (alias, score, label)
}

pub(crate) fn resolve_group_for_alias(
    alias: &str,
    compiled: &CompiledConfig,
    default_group: &str,
) -> String {
    for entry in compiled.group_entries.iter() {
        if let Some(channels) = entry.channels.as_ref()
            && channels.iter().any(|c| c == alias)
        {
            return entry.group.clone();
        }
        if let Some(regex) = entry.regex.as_ref()
            && regex.is_match(alias)
        {
            return entry.group.clone();
        }
    }
    default_group.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, compile_config};

    fn sample_config() -> Config {
        toml::from_str(
            r#"
[alias]
mode = "first_match"

[[alias.rules]]
type = "regex"
pattern = "(?i)^CCTV\\s*[-\\s]*\\s*4K.*$"
replace = "CCTV4K"

[[alias.rules]]
type = "regex"
pattern = "(?i)^CCTV\\s*[-\\s]*\\s*4.*$"
replace = "CCTV4"

[[alias.rules]]
type = "regex"
pattern = "(?i)^CCTV\\s*[-\\s]*\\s*5(?:\\s*(?:[+＋]|P(?:LUS)?)).*$"
replace = "CCTV5+"

[[alias.rules]]
type = "regex"
pattern = "(?i)^CCTV[-\\s]*(\\d{1,2}(?:\\s*K)?).*"
replace = "CCTV$1"

[[alias.rules]]
type = "regex"
pattern = "(?i)^(.+?)(?:[-\\s]|高清|超清|超高清|4K|[25]0P|时移|专用|测试)*$"
replace = "$1"
"#,
        )
        .expect("sample config should parse")
    }

    fn make_entry(index: usize, raw_name: &str) -> ChannelEntry {
        ChannelEntry {
            key: format!("gd:{index}:{index}"),
            source: "gd-iptv".to_string(),
            channel_id: Some(index as u64),
            url: format!("http://proxy/udp/239.0.0.{index}:5000"),
            raw_name: raw_name.to_string(),
            alias_name: String::new(),
            group: String::new(),
            tvg_id: index.to_string(),
            tvg_name: raw_name.to_string(),
            tvg_logo: String::new(),
            tvg_chno: index.to_string(),
            catchup: String::new(),
            catchup_source: String::new(),
            catchup_attr: String::new(),
            extras: BTreeMap::new(),
            resolution_score: 0,
            resolution_label: "Unknown".to_string(),
            original_index: index,
        }
    }

    #[test]
    fn cctv5_and_cctv5_plus_stay_distinct() {
        let config = sample_config();
        let compiled = compile_config(&config).expect("config should compile");

        assert_eq!(
            apply_alias("CCTV5体育高清-测试", &config, &compiled),
            "CCTV5"
        );
        assert_eq!(
            apply_alias("CCTV5+体育高清-测试", &config, &compiled),
            "CCTV5+"
        );
        assert_eq!(
            apply_alias("CCTV5＋体育高清-测试", &config, &compiled),
            "CCTV5+"
        );
        assert_eq!(
            apply_alias("CCTV5 PLUS体育高清-测试", &config, &compiled),
            "CCTV5+"
        );
    }

    #[test]
    fn assign_groups_preserves_channel_order_first_claim_regex_and_resolution_sorting() {
        let config: Config = toml::from_str(
            r#"
[alias]
mode = "first_match"

[[alias.rules]]
type = "regex"
pattern = "(?i)^(.+?)(?:[-\\s]|高清|4K)*$"
replace = "$1"

[[resolution.rules]]
pattern = "(?i)4k"
score = 400
label = "R4K"

[[resolution.rules]]
pattern = "高清"
score = 200
label = "Hd"

[groups]
default_group = "其他"

[[groups.entries]]
group = "央视"
channels = ["CCTV2", "CCTV1"]

[[groups.entries]]
group = "卫视"
channels = ["CCTV1", "广东卫视"]

[[groups.entries]]
group = "体育"
match_regex = "^体育.*"
"#,
        )
        .unwrap();
        let compiled = compile_config(&config).unwrap();
        let ctx = EntryBuildContext {
            config: &config,
            compiled: &compiled,
        };

        let entries = vec![
            make_entry(0, "地方台"),
            make_entry(1, "CCTV1高清"),
            make_entry(2, "CCTV1-4K"),
            make_entry(3, "体育赛事"),
            make_entry(4, "CCTV2高清"),
            make_entry(5, "广东卫视高清"),
        ];

        let finalized = finalize_entries(entries, &ctx);
        let summary: Vec<(&str, &str, i32)> = finalized
            .iter()
            .map(|e| (e.alias_name.as_str(), e.group.as_str(), e.resolution_score))
            .collect();

        assert_eq!(
            summary,
            vec![
                ("CCTV2", "央视", 200),
                // CCTV1 4K sorted ahead of CCTV1 HD, and claimed by 央视 (not duplicated in 卫视).
                ("CCTV1", "央视", 400),
                ("CCTV1", "央视", 200),
                ("广东卫视", "卫视", 200),
                ("体育赛事", "体育", 0),
                ("地方台", "其他", 0),
            ]
        );
    }
}
