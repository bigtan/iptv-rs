use crate::iptv::Channel;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub(crate) struct CachedText {
    pub(crate) expires_at: Instant,
    pub(crate) body: String,
}

pub(crate) struct CachedChannels {
    pub(crate) expires_at: Instant,
    pub(crate) channels: Vec<Channel>,
}

pub(crate) struct CachedBytes {
    pub(crate) expires_at: Instant,
    pub(crate) body: Vec<u8>,
}

pub(crate) const PLAYLIST_CACHE_TTL: Duration = Duration::from_secs(30);
pub(crate) const XMLTV_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
pub(crate) const MANAGE_CACHE_TTL: Duration = Duration::from_secs(30);
pub(crate) const CHANNEL_CACHE_TTL: Duration = Duration::from_secs(60);
pub(crate) const EPG_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
pub(crate) const ICON_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
pub(crate) const MAX_OUTPUT_CACHE_ENTRIES: usize = 128;
pub(crate) const MAX_UPSTREAM_CACHE_ENTRIES: usize = 32;
pub(crate) const MAX_ICON_CACHE_ENTRIES: usize = 512;

pub(crate) fn get_text(cache: &Mutex<HashMap<String, CachedText>>, key: &str) -> Option<String> {
    let mut cache = cache.lock().ok()?;
    let cached = cache.get(key)?;
    if cached.expires_at <= Instant::now() {
        cache.remove(key);
        return None;
    }
    Some(cached.body.clone())
}

pub(crate) fn put_text(
    cache: &Mutex<HashMap<String, CachedText>>,
    key: String,
    body: String,
    ttl: Duration,
) {
    if let Ok(mut cache) = cache.lock() {
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        if cache.len() >= MAX_OUTPUT_CACHE_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            CachedText {
                expires_at: now + ttl,
                body,
            },
        );
    }
}

pub(crate) fn put_stale(cache: &Mutex<HashMap<String, String>>, key: String, body: String) {
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= MAX_OUTPUT_CACHE_ENTRIES
            && let Some(key) = cache.keys().next().cloned()
        {
            cache.remove(&key);
        }
        cache.insert(key, body);
    }
}
