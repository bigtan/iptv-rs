use crate::{fcc::FccOptions, proxy};
use actix_web::web::Bytes;
use anyhow::Result;
use futures_core::Stream;
use futures_util::StreamExt;
use log::{debug, warn};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddrV4,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::bytes::BytesMut;

const MAX_PROXY_STREAMS: usize = 64;
const BATCH_BYTES: usize = 16 * 1024;
const BATCH_RESERVE_SLACK: usize = 2048;
const BUFFER_CHUNKS: usize = 128;
const PAT_LOOKBACK_CHUNKS: u64 = 64;
const TS_PACKET_LEN: usize = 188;
const BATCH_FLUSH: Duration = Duration::from_millis(2);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SharedUdpKey {
    if_name: String,
    addr: SocketAddrV4,
}

impl fmt::Display for SharedUdpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.if_name.is_empty() {
            write!(f, "udp|{}", self.addr)
        } else {
            write!(f, "udp|{}|{}", self.if_name, self.addr)
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedProxyRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    slots: Arc<Semaphore>,
    hubs: Mutex<HashMap<SharedUdpKey, Arc<SharedProxyHub>>>,
}

struct SharedProxyHub {
    inner: Mutex<SharedProxyInner>,
    notify: Notify,
    zero_receivers: Notify,
    receivers: AtomicUsize,
}

struct SharedProxyInner {
    chunks: VecDeque<(u64, Bytes)>,
    next_seq: u64,
    last_pat_seq: Option<u64>,
    closed: bool,
}

pub(crate) struct SharedProxyReceiver {
    hub: Arc<SharedProxyHub>,
    next_seq: u64,
}

#[derive(Debug)]
pub(crate) enum SharedProxyRecvError {
    Lagged(u64),
    Closed,
}

pub(crate) enum SharedProxySubscribeError {
    Busy,
    Poisoned,
}

impl SharedProxyRegistry {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                slots: Arc::new(Semaphore::new(MAX_PROXY_STREAMS)),
                hubs: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn try_acquire(&self) -> Result<OwnedSemaphorePermit, SharedProxySubscribeError> {
        self.inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| SharedProxySubscribeError::Busy)
    }

    pub(crate) fn subscribe_udp(
        &self,
        addr: SocketAddrV4,
        if_name: Option<String>,
        fcc: Option<FccOptions>,
    ) -> Result<SharedProxyReceiver, SharedProxySubscribeError> {
        let key = shared_udp_key(if_name.as_deref(), addr);
        debug!(
            "Subscribe shared UDP key={} multicast={} interface={:?} fcc={:?}",
            key,
            addr,
            if_name,
            fcc.as_ref().map(|value| value.server)
        );
        if let Ok(hubs) = self.inner.hubs.lock()
            && let Some(hub) = hubs.get(&key)
        {
            return Ok(hub.subscribe());
        }

        let permit = self.try_acquire()?;
        let hub = Arc::new(SharedProxyHub::new());
        {
            let mut hubs = self
                .inner
                .hubs
                .lock()
                .map_err(|_| SharedProxySubscribeError::Poisoned)?;
            if let Some(existing) = hubs.get(&key) {
                return Ok(existing.subscribe());
            }
            hubs.insert(key.clone(), Arc::clone(&hub));
        }

        let stream = proxy::udp_source(addr, if_name, fcc, permit);
        let receiver = hub.subscribe();
        self.spawn_source(key, hub, stream);
        Ok(receiver)
    }

    fn spawn_source<S>(&self, key: SharedUdpKey, hub: Arc<SharedProxyHub>, stream: S)
    where
        S: Stream<Item = Result<Bytes>> + Send + 'static,
    {
        let registry = self.clone();
        tokio::spawn(async move {
            let mut stream = Box::pin(stream);
            let mut pending = BytesMut::with_capacity(BATCH_BYTES * 2);
            let mut pending_since: Option<Instant> = None;
            loop {
                if hub.receiver_count() == 0 {
                    if let Ok(mut hubs) = registry.inner.hubs.lock() {
                        if hub.receiver_count() > 0 {
                            continue;
                        }
                        if hubs.get(&key).is_some_and(|cur| Arc::ptr_eq(cur, &hub)) {
                            hubs.remove(&key);
                        }
                    }
                    flush_pending(&hub, &mut pending);
                    hub.close();
                    return;
                }
                if pending_since.is_some_and(|started| {
                    Instant::now().saturating_duration_since(started) >= BATCH_FLUSH
                }) {
                    flush_pending(&hub, &mut pending);
                    pending_since = None;
                }

                tokio::select! {
                    _ = hub.zero_receivers.notified() => {}
                    item = stream.next() => {
                        match item {
                            Some(Ok(bytes)) => {
                                if bytes.is_empty() {
                                    continue;
                                }
                                if pending.is_empty() {
                                    let min_cap = BATCH_BYTES + BATCH_RESERVE_SLACK;
                                    if pending.capacity() < min_cap {
                                        pending.reserve(min_cap - pending.capacity());
                                    }
                                    pending_since = Some(Instant::now());
                                }
                                pending.extend_from_slice(bytes.as_ref());
                                if pending.len() >= BATCH_BYTES {
                                    flush_pending(&hub, &mut pending);
                                    pending_since = None;
                                }
                            }
                            Some(Err(error)) => {
                                flush_pending(&hub, &mut pending);
                                warn!("Shared proxy stream {key} ended with error: {error}");
                                break;
                            }
                            None => {
                                flush_pending(&hub, &mut pending);
                                break;
                            }
                        }
                    }
                    _ = async {
                        match pending_since {
                            Some(started) => tokio::time::sleep(batch_wait(Some(started), Instant::now())).await,
                            None => std::future::pending::<()>().await,
                        }
                    }, if pending_since.is_some() => {
                        flush_pending(&hub, &mut pending);
                        pending_since = None;
                    }
                }
            }
            if let Ok(mut hubs) = registry.inner.hubs.lock()
                && hubs.get(&key).is_some_and(|cur| Arc::ptr_eq(cur, &hub))
            {
                hubs.remove(&key);
            }
            hub.close();
        });
    }
}

fn batch_wait(pending_since: Option<Instant>, now: Instant) -> Duration {
    pending_since
        .map(|started| BATCH_FLUSH.saturating_sub(now.saturating_duration_since(started)))
        .unwrap_or(BATCH_FLUSH)
}

fn flush_pending(hub: &SharedProxyHub, pending: &mut BytesMut) {
    if !pending.is_empty() {
        hub.push(pending.split().freeze());
    }
}

fn shared_udp_key(if_name: Option<&str>, addr: SocketAddrV4) -> SharedUdpKey {
    SharedUdpKey {
        if_name: if_name.unwrap_or_default().to_string(),
        addr,
    }
}

fn contains_mpegts_pat(data: &[u8]) -> bool {
    data.as_chunks::<TS_PACKET_LEN>().0.iter().any(|pkt| {
        pkt[0] == 0x47
            && (pkt[1] & 0x40) != 0
            && ((((pkt[1] & 0x1f) as u16) << 8) | (pkt[2] as u16)) == 0
    })
}

impl SharedProxyHub {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SharedProxyInner {
                chunks: VecDeque::with_capacity(BUFFER_CHUNKS),
                next_seq: 0,
                last_pat_seq: None,
                closed: false,
            }),
            notify: Notify::new(),
            zero_receivers: Notify::new(),
            receivers: AtomicUsize::new(0),
        }
    }

    fn subscribe(self: &Arc<Self>) -> SharedProxyReceiver {
        self.receivers.fetch_add(1, Ordering::AcqRel);
        let next_seq = self
            .inner
            .lock()
            .map(|inner| {
                if let Some(pat_seq) = inner.last_pat_seq
                    && let Some((first_seq, _)) = inner.chunks.front()
                    && pat_seq >= *first_seq
                    && inner.next_seq.saturating_sub(pat_seq) <= PAT_LOOKBACK_CHUNKS
                {
                    pat_seq
                } else {
                    inner.next_seq
                }
            })
            .unwrap_or(0);
        SharedProxyReceiver {
            hub: Arc::clone(self),
            next_seq,
        }
    }

    fn receiver_count(&self) -> usize {
        self.receivers.load(Ordering::Acquire)
    }

    fn push(&self, bytes: Bytes) {
        let has_pat = contains_mpegts_pat(&bytes);
        if let Ok(mut inner) = self.inner.lock() {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            if has_pat {
                inner.last_pat_seq = Some(seq);
            }
            inner.chunks.push_back((seq, bytes));
            while inner.chunks.len() > BUFFER_CHUNKS {
                inner.chunks.pop_front();
            }
            if let Some((first_seq, _)) = inner.chunks.front()
                && inner
                    .last_pat_seq
                    .is_some_and(|pat_seq| pat_seq < *first_seq)
            {
                inner.last_pat_seq = None;
            }
        }
        self.notify.notify_waiters();
    }

    fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.closed = true;
        }
        self.notify.notify_waiters();
    }
}

impl Drop for SharedProxyReceiver {
    fn drop(&mut self) {
        if self.hub.receivers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.hub.zero_receivers.notify_one();
        }
    }
}

impl SharedProxyReceiver {
    pub(crate) async fn recv(&mut self) -> Result<Bytes, SharedProxyRecvError> {
        loop {
            let notified = self.hub.notify.notified();
            {
                let inner = self
                    .hub
                    .inner
                    .lock()
                    .map_err(|_| SharedProxyRecvError::Closed)?;
                if let Some((first_seq, _)) = inner.chunks.front()
                    && self.next_seq < *first_seq
                {
                    let lagged = *first_seq - self.next_seq;
                    self.next_seq = *first_seq;
                    return Err(SharedProxyRecvError::Lagged(lagged));
                }
                if let Some((first_seq, _)) = inner.chunks.front() {
                    let offset = self.next_seq.saturating_sub(*first_seq) as usize;
                    if let Some((seq, bytes)) = inner.chunks.get(offset)
                        && *seq == self.next_seq
                    {
                        self.next_seq += 1;
                        return Ok(bytes.clone());
                    }
                }
                if inner.closed {
                    return Err(SharedProxyRecvError::Closed);
                }
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ts_packet(pusi: bool, pid: u16, fill: u8) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [fill; TS_PACKET_LEN];
        pkt[0] = 0x47;
        pkt[1] = (if pusi { 0x40 } else { 0x00 }) | ((pid >> 8) as u8 & 0x1f);
        pkt[2] = (pid & 0xff) as u8;
        pkt[3] = 0x10;
        pkt
    }

    #[actix_web::test]
    async fn new_subscriber_starts_at_live_edge() {
        let hub = Arc::new(SharedProxyHub::new());
        hub.push(Bytes::from_static(b"old"));
        let mut receiver = hub.subscribe();
        hub.push(Bytes::from_static(b"live"));

        assert_eq!(receiver.recv().await.unwrap(), Bytes::from_static(b"live"));
    }

    #[actix_web::test]
    async fn new_subscriber_rewinds_to_recent_pat_chunk() {
        let hub = Arc::new(SharedProxyHub::new());
        let non_pat = Bytes::copy_from_slice(&make_ts_packet(true, 0x0100, 0xaa));
        let pat_no_pusi = Bytes::copy_from_slice(&make_ts_packet(false, 0x0000, 0xbb));
        let pat = Bytes::copy_from_slice(&make_ts_packet(true, 0x0000, 0xcc));
        let video = Bytes::copy_from_slice(&make_ts_packet(false, 0x0101, 0xdd));

        hub.push(non_pat);
        hub.push(pat_no_pusi);
        hub.push(pat.clone());
        hub.push(video.clone());

        let mut second_viewer = hub.subscribe();
        assert_eq!(second_viewer.recv().await.unwrap(), pat);
        assert_eq!(second_viewer.recv().await.unwrap(), video);
    }

    #[actix_web::test]
    async fn stale_pat_beyond_lookback_starts_at_live_edge() {
        let hub = Arc::new(SharedProxyHub::new());
        let pat = Bytes::copy_from_slice(&make_ts_packet(true, 0x0000, 0xcc));
        let filler = Bytes::copy_from_slice(&make_ts_packet(false, 0x0101, 0x11));

        hub.push(pat);
        for _ in 0..PAT_LOOKBACK_CHUNKS {
            hub.push(filler.clone());
        }

        // 1 PAT + 64 filler chunks => next_seq is 65, pat_seq is 0 (65 - 0 > 64).
        let mut late_viewer = hub.subscribe();
        let live = Bytes::copy_from_slice(&make_ts_packet(false, 0x0101, 0x22));
        hub.push(live.clone());
        assert_eq!(late_viewer.recv().await.unwrap(), live);
    }

    #[actix_web::test]
    async fn dropping_last_receiver_wakes_idle_source_immediately() {
        let registry = SharedProxyRegistry::new();
        let addr: SocketAddrV4 = "239.1.1.9:5000".parse().unwrap();
        let key = shared_udp_key(Some("eth0"), addr);
        let hub = Arc::new(SharedProxyHub::new());
        registry
            .inner
            .hubs
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::clone(&hub));

        let receiver = hub.subscribe();
        registry.spawn_source(
            key.clone(),
            Arc::clone(&hub),
            futures_util::stream::pending(),
        );

        // Let the spawned task park on `tokio::select!` with an idle stream (no 2ms timer).
        tokio::task::yield_now().await;
        drop(receiver);

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if !registry.inner.hubs.lock().unwrap().contains_key(&key)
                    && hub.inner.lock().unwrap().closed
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle source should exit promptly when last receiver drops");
    }

    #[actix_web::test]
    async fn reports_lag_after_buffer_rollover() {
        let hub = Arc::new(SharedProxyHub::new());
        let mut receiver = hub.subscribe();
        for _ in 0..=BUFFER_CHUNKS {
            hub.push(Bytes::from_static(b"packet"));
        }
        assert!(matches!(
            receiver.recv().await,
            Err(SharedProxyRecvError::Lagged(1))
        ));
    }

    #[test]
    fn batch_deadline_is_not_reset_by_later_packets() {
        let started = Instant::now();

        assert_eq!(
            batch_wait(Some(started), started + Duration::from_millis(1)),
            Duration::from_millis(1)
        );
        assert_eq!(
            batch_wait(Some(started), started + BATCH_FLUSH),
            Duration::ZERO
        );
    }

    #[test]
    fn key_uses_only_interface_and_addr() {
        let addr = SocketAddrV4::new("239.1.1.1".parse().unwrap(), 5000);
        let other_addr = SocketAddrV4::new("239.1.1.2".parse().unwrap(), 5000);

        assert_eq!(
            shared_udp_key(Some("iptv0"), addr),
            shared_udp_key(Some("iptv0"), addr)
        );
        assert_eq!(shared_udp_key(None, addr), shared_udp_key(Some(""), addr));
        assert_ne!(
            shared_udp_key(Some("iptv0"), addr),
            shared_udp_key(Some("iptv1"), addr)
        );
        assert_ne!(
            shared_udp_key(Some("iptv0"), addr),
            shared_udp_key(Some("iptv0"), other_addr)
        );
    }
}
