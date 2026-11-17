use crate::iptv::Channel;
use anyhow::{Result, anyhow};
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

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
pub(crate) const MAX_IN_FLIGHT_UPSTREAM: usize = 32;
pub(crate) const MAX_IN_FLIGHT_ICONS: usize = 128;

struct FlightEntry {
    gate: Arc<AsyncMutex<()>>,
    waiters: usize,
}

pub(crate) struct FlightTable {
    entries: Mutex<HashMap<String, FlightEntry>>,
    max_keys: usize,
}

struct FlightRegistration<'a> {
    table: &'a FlightTable,
    key: String,
}

impl Drop for FlightRegistration<'_> {
    fn drop(&mut self) {
        let mut entries = self.table.entries.lock().unwrap_or_else(|e| e.into_inner());
        let should_remove = if let Some(entry) = entries.get_mut(&self.key) {
            entry.waiters = entry.waiters.saturating_sub(1);
            entry.waiters == 0
        } else {
            false
        };
        if should_remove {
            entries.remove(&self.key);
        }
    }
}

pub(crate) struct FlightGuard<'a> {
    // Field drop order is significant: release the async mutex first so queued
    // waiters wake immediately, then decrement/remove the table registration.
    _mutex_guard: OwnedMutexGuard<()>,
    _registration: FlightRegistration<'a>,
}

impl FlightTable {
    pub(crate) fn new(max_keys: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_keys,
        }
    }

    pub(crate) async fn acquire(&self, key: &str) -> Result<FlightGuard<'_>> {
        let (gate, registration) = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = entries.get_mut(key) {
                entry.waiters += 1;
                (
                    entry.gate.clone(),
                    FlightRegistration {
                        table: self,
                        key: key.to_string(),
                    },
                )
            } else {
                if entries.len() >= self.max_keys {
                    return Err(anyhow!(
                        "Too many concurrent upstream requests in flight (limit {})",
                        self.max_keys
                    ));
                }
                let gate = Arc::new(AsyncMutex::new(()));
                entries.insert(
                    key.to_string(),
                    FlightEntry {
                        gate: gate.clone(),
                        waiters: 1,
                    },
                );
                (
                    gate,
                    FlightRegistration {
                        table: self,
                        key: key.to_string(),
                    },
                )
            }
        };

        let mutex_guard = gate.lock_owned().await;
        Ok(FlightGuard {
            _mutex_guard: mutex_guard,
            _registration: registration,
        })
    }

    #[cfg(test)]
    pub(crate) fn active_key_count(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

pub(crate) struct CacheStore {
    generation: AtomicU64,
    playlist: Mutex<HashMap<String, CachedText>>,
    xmltv: Mutex<HashMap<String, CachedText>>,
    manage_json: Mutex<HashMap<String, CachedText>>,
    manage_html: Mutex<HashMap<String, CachedText>>,
    manage_raw: Mutex<HashMap<String, CachedText>>,
    stale_playlists: Mutex<HashMap<String, String>>,
    stale_xmltv: Mutex<HashMap<String, String>>,
    upstream_channels: Mutex<HashMap<String, CachedChannels>>,
    icons: Mutex<HashMap<String, CachedBytes>>,
    upstream_flights: FlightTable,
    icon_flights: FlightTable,
}

impl Default for CacheStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheStore {
    pub(crate) fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            playlist: Mutex::new(HashMap::new()),
            xmltv: Mutex::new(HashMap::new()),
            manage_json: Mutex::new(HashMap::new()),
            manage_html: Mutex::new(HashMap::new()),
            manage_raw: Mutex::new(HashMap::new()),
            stale_playlists: Mutex::new(HashMap::new()),
            stale_xmltv: Mutex::new(HashMap::new()),
            upstream_channels: Mutex::new(HashMap::new()),
            icons: Mutex::new(HashMap::new()),
            upstream_flights: FlightTable::new(MAX_IN_FLIGHT_UPSTREAM),
            icon_flights: FlightTable::new(MAX_IN_FLIGHT_ICONS),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn clear_all(&self) {
        // Advance generation BEFORE clearing maps so any pre-reload in-flight
        // task either writes before we clear (and gets wiped) or observes the
        // incremented generation inside `put_*` (and skips writing).
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.playlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.xmltv.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.manage_json
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.manage_html
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.manage_raw
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.stale_playlists
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.stale_xmltv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.upstream_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.icons.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(crate) fn get_playlist(&self, key: &str) -> Option<String> {
        get_text(&self.playlist, key)
    }

    pub(crate) fn put_playlist(&self, expected_gen: u64, key: String, body: String) {
        put_text(
            &self.playlist,
            &self.generation,
            expected_gen,
            key.clone(),
            body.clone(),
            PLAYLIST_CACHE_TTL,
        );
        put_stale(
            &self.stale_playlists,
            &self.generation,
            expected_gen,
            key,
            body,
        );
    }

    pub(crate) fn get_stale_playlist(&self, key: &str) -> Option<String> {
        self.stale_playlists
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    pub(crate) fn get_xmltv(&self, key: &str) -> Option<String> {
        get_text(&self.xmltv, key)
    }

    pub(crate) fn put_xmltv(&self, expected_gen: u64, key: String, body: String) {
        put_text(
            &self.xmltv,
            &self.generation,
            expected_gen,
            key.clone(),
            body.clone(),
            XMLTV_CACHE_TTL,
        );
        put_stale(&self.stale_xmltv, &self.generation, expected_gen, key, body);
    }

    pub(crate) fn get_stale_xmltv(&self, key: &str) -> Option<String> {
        self.stale_xmltv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    pub(crate) fn get_manage_json(&self, key: &str) -> Option<String> {
        get_text(&self.manage_json, key)
    }

    pub(crate) fn put_manage_json(&self, expected_gen: u64, key: String, body: String) {
        put_text(
            &self.manage_json,
            &self.generation,
            expected_gen,
            key,
            body,
            MANAGE_CACHE_TTL,
        );
    }

    pub(crate) fn get_manage_html(&self, key: &str) -> Option<String> {
        get_text(&self.manage_html, key)
    }

    pub(crate) fn put_manage_html(&self, expected_gen: u64, key: String, body: String) {
        put_text(
            &self.manage_html,
            &self.generation,
            expected_gen,
            key,
            body,
            MANAGE_CACHE_TTL,
        );
    }

    pub(crate) fn get_manage_raw(&self, key: &str) -> Option<String> {
        get_text(&self.manage_raw, key)
    }

    pub(crate) fn put_manage_raw(&self, expected_gen: u64, key: String, body: String) {
        put_text(
            &self.manage_raw,
            &self.generation,
            expected_gen,
            key,
            body,
            MANAGE_CACHE_TTL,
        );
    }

    fn get_channels(&self, key: &str) -> Option<Vec<Channel>> {
        let mut cache = self
            .upstream_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        cache.get(key).map(|cached| cached.channels.clone())
    }

    fn put_channels(&self, expected_gen: u64, key: String, channels: Vec<Channel>, ttl: Duration) {
        let mut cache = self
            .upstream_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.generation.load(Ordering::Acquire) != expected_gen {
            return;
        }
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        if cache.len() >= MAX_UPSTREAM_CACHE_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at)
                .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            CachedChannels {
                expires_at: now + ttl,
                channels,
            },
        );
    }

    pub(crate) async fn get_or_try_init_channels<F, Fut>(
        &self,
        key: String,
        ttl: Duration,
        fetch: F,
    ) -> Result<Vec<Channel>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<Channel>>>,
    {
        if let Some(channels) = self.get_channels(&key) {
            return Ok(channels);
        }

        let _flight_guard = self.upstream_flights.acquire(&key).await?;
        if let Some(channels) = self.get_channels(&key) {
            return Ok(channels);
        }

        let expected_gen = self.generation();
        let channels = fetch().await?;
        self.put_channels(expected_gen, key, channels.clone(), ttl);
        Ok(channels)
    }

    fn get_icon(&self, key: &str) -> Option<Vec<u8>> {
        let mut cache = self.icons.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        cache.get(key).map(|cached| cached.body.clone())
    }

    fn put_icon(&self, expected_gen: u64, key: String, body: Vec<u8>, ttl: Duration) {
        let mut cache = self.icons.lock().unwrap_or_else(|e| e.into_inner());
        if self.generation.load(Ordering::Acquire) != expected_gen {
            return;
        }
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
        if cache.len() >= MAX_ICON_CACHE_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at)
                .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            CachedBytes {
                expires_at: now + ttl,
                body,
            },
        );
    }

    pub(crate) async fn get_or_try_init_icon<F, Fut>(
        &self,
        key: String,
        fetch: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        if let Some(icon) = self.get_icon(&key) {
            return Ok(icon);
        }

        let _flight_guard = self.icon_flights.acquire(&key).await?;
        if let Some(icon) = self.get_icon(&key) {
            return Ok(icon);
        }

        let expected_gen = self.generation();
        let icon = fetch().await?;
        self.put_icon(expected_gen, key, icon.clone(), ICON_CACHE_TTL);
        Ok(icon)
    }

    #[cfg(test)]
    pub(crate) fn upstream_flight_count(&self) -> usize {
        self.upstream_flights.active_key_count()
    }
}

fn get_text(cache: &Mutex<HashMap<String, CachedText>>, key: &str) -> Option<String> {
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let cached = cache.get(key)?;
    if cached.expires_at <= Instant::now() {
        cache.remove(key);
        return None;
    }
    Some(cached.body.clone())
}

fn put_text(
    cache: &Mutex<HashMap<String, CachedText>>,
    generation: &AtomicU64,
    expected_gen: u64,
    key: String,
    body: String,
    ttl: Duration,
) {
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if generation.load(Ordering::Acquire) != expected_gen {
        return;
    }
    let now = Instant::now();
    cache.retain(|_, cached| cached.expires_at > now);
    if cache.len() >= MAX_OUTPUT_CACHE_ENTRIES
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(k, _)| k.clone())
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

fn put_stale(
    cache: &Mutex<HashMap<String, String>>,
    generation: &AtomicU64,
    expected_gen: u64,
    key: String,
    body: String,
) {
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if generation.load(Ordering::Acquire) != expected_gen {
        return;
    }
    if cache.len() >= MAX_OUTPUT_CACHE_ENTRIES
        && !cache.contains_key(&key)
        && let Some(evict_key) = cache.keys().next().cloned()
    {
        cache.remove(&evict_key);
    }
    cache.insert(key, body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;

    #[test]
    fn text_and_stale_caches_expire_and_bound_entries() {
        let caches = CacheStore::new();
        let epoch = caches.generation();

        put_text(
            &caches.playlist,
            &caches.generation,
            epoch,
            "expired".to_string(),
            "body".to_string(),
            Duration::ZERO,
        );
        assert!(caches.get_playlist("expired").is_none());

        for idx in 0..=MAX_OUTPUT_CACHE_ENTRIES {
            caches.put_playlist(epoch, idx.to_string(), format!("val-{idx}"));
        }
        assert_eq!(
            caches.playlist.lock().unwrap().len(),
            MAX_OUTPUT_CACHE_ENTRIES
        );
        assert_eq!(
            caches.stale_playlists.lock().unwrap().len(),
            MAX_OUTPUT_CACHE_ENTRIES
        );
    }

    #[tokio::test]
    async fn single_flight_coalesces_and_cleans_up_on_cancellation() {
        let caches = Arc::new(CacheStore::new());
        let entered = Arc::new(Notify::new());
        let hold = Arc::new(Notify::new());

        let caches_leader = caches.clone();
        let entered_leader = entered.clone();
        let hold_leader = hold.clone();
        let leader = tokio::spawn(async move {
            caches_leader
                .get_or_try_init_channels("k1".to_string(), CHANNEL_CACHE_TTL, || async move {
                    entered_leader.notify_one();
                    hold_leader.notified().await;
                    Ok(Vec::new())
                })
                .await
        });

        entered.notified().await;
        assert_eq!(caches.upstream_flight_count(), 1);

        // Simulate client disconnect cancelling the in-flight leader future.
        leader.abort();
        let _ = leader.await;

        assert_eq!(
            caches.upstream_flight_count(),
            0,
            "RAII guard must remove cancelled flight entry on drop"
        );

        // Subsequent requests for the same key must succeed without deadlocking,
        // and concurrent callers must coalesce onto a single upstream fetch.
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Notify::new());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let c = caches.clone();
            let calls = calls.clone();
            let start = start.clone();
            handles.push(tokio::spawn(async move {
                c.get_or_try_init_channels("k1".to_string(), CHANNEL_CACHE_TTL, || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    start.notified().await;
                    Ok(vec![Channel {
                        id: 42,
                        name: "CCTV1".to_string(),
                        rtsp: "rtsp://10.0.0.1/1".to_string(),
                        igmp: None,
                        fcc_server: None,
                        epg: Vec::new(),
                        time_shift_url: None,
                    }])
                })
                .await
                .unwrap()
            }));
        }

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        start.notify_waiters();

        for h in handles {
            let res = h.await.unwrap();
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, 42);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(caches.upstream_flight_count(), 0);
    }

    #[tokio::test]
    async fn flight_table_bounds_distinct_keys_while_allowing_coalescing() {
        let table = Arc::new(FlightTable::new(2));
        let g1 = table.acquire("a").await.unwrap();
        let g2 = table.acquire("b").await.unwrap();

        // A third distinct key must be rejected while 2 distinct flights are active.
        assert!(table.acquire("c").await.is_err());

        // Dropping one guard immediately frees capacity for a new key.
        drop(g1);
        let g3 = table.acquire("c").await.unwrap();
        drop(g2);
        drop(g3);
        assert_eq!(table.active_key_count(), 0);
    }

    #[tokio::test]
    async fn clear_all_generation_prevents_pre_reload_stale_writes() {
        let caches = Arc::new(CacheStore::new());
        let old_gen = caches.generation();
        caches.put_playlist(old_gen, "p".to_string(), "before".to_string());
        assert_eq!(caches.get_playlist("p").as_deref(), Some("before"));

        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let caches_bg = caches.clone();
        let entered_bg = entered.clone();
        let finish_bg = finish.clone();

        let bg = tokio::spawn(async move {
            caches_bg
                .get_or_try_init_icon("logo-1".to_string(), || async move {
                    entered_bg.notify_one();
                    finish_bg.notified().await;
                    Ok(vec![1, 2, 3])
                })
                .await
                .unwrap()
        });

        entered.notified().await;
        // Trigger reload clear while `bg` is mid-fetch under `old_gen`.
        caches.clear_all();
        assert_ne!(caches.generation(), old_gen);
        assert!(caches.get_playlist("p").is_none());

        // Stale output write using `old_gen` must be ignored.
        caches.put_playlist(old_gen, "p".to_string(), "stale".to_string());
        assert!(caches.get_playlist("p").is_none());
        assert!(caches.get_stale_playlist("p").is_none());

        // Let the pre-reload icon task finish; it still returns bytes to its own
        // caller, but must NOT populate the post-reload cache.
        finish.notify_one();
        assert_eq!(bg.await.unwrap(), vec![1, 2, 3]);
        assert!(caches.get_icon("logo-1").is_none());
    }
}
