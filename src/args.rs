use clap::Parser;

#[derive(Parser, Clone, Debug)]
#[command(name = "iptv-rs")]
pub(crate) struct Args {
    #[arg(short = 'u', long)]
    pub(crate) user: Option<String>,

    #[arg(short = 'p', long)]
    pub(crate) passwd: Option<String>,

    #[arg(short = 'm', long)]
    pub(crate) mac: Option<String>,

    #[arg(short = 'i', long)]
    pub(crate) imei: Option<String>,

    #[arg(short = 'b', long)]
    pub(crate) bind: Option<String>,

    #[arg(long)]
    pub(crate) bind_interface: Option<String>,

    #[arg(long)]
    pub(crate) workers: Option<usize>,

    #[arg(short = 'a', long)]
    pub(crate) address: Option<String>,

    #[arg(short = 'I', long)]
    pub(crate) interface: Option<String>,

    #[arg(short = 'c', long)]
    pub(crate) config: Option<String>,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub(crate) udp_proxy: bool,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub(crate) rtsp_proxy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpstreamCredentials {
    pub(crate) user: String,
    pub(crate) passwd: String,
    pub(crate) mac: String,
    pub(crate) imei: String,
    pub(crate) address: String,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveArgs {
    pub(crate) upstream: Option<UpstreamCredentials>,
    pub(crate) bind: String,
    pub(crate) bind_interface: Option<String>,
    pub(crate) workers: Option<usize>,
    pub(crate) interface: Option<String>,
    pub(crate) udp_proxy: bool,
    pub(crate) rtsp_proxy: bool,
    pub(crate) fcc_enabled: bool,
    pub(crate) fcc_max_redirects: usize,
    pub(crate) fcc_switch_extra_packets: usize,
    pub(crate) fcc_switch_min_unicast_ms: u64,
}
