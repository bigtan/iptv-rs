use crate::{fcc::FccOptions, proxy};
use actix_web::web::Bytes;
use anyhow::Result;
use futures_core::Stream;
use futures_util::StreamExt;
use log::{debug, warn};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddrV4,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

const MAX_PROXY_STREAMS: usize = 64;
const BATCH_BYTES: usize = 16 * 1024;
const BUFFER_CHUNKS: usize = 512;
const BATCH_FLUSH: Duration = Duration::from_millis(2);

#[derive(Clone)]
pub(crate) struct SharedProxyRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    slots: Arc<Semaphore>,
    hubs: Mutex<HashMap<String, Arc<SharedProxyHub>>>,
}

struct SharedProxyHub {
    inner: Mutex<SharedProxyInner>,
    notify: Notify,
}

struct SharedProxyInner {
    chunks: VecDeque<(u64, Bytes)>,
    next_seq: u64,
    receivers: usize,
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
        let key = shared_udp_key(&addr, if_name.as_deref(), fcc.as_ref());
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
            if let Some(existing) = hubs.get(&key).cloned() {
                return Ok(existing.subscribe());
            }
            hubs.insert(key.clone(), Arc::clone(&hub));
        }

        let stream = proxy::udp_source(addr, if_name, fcc, permit);
        let receiver = hub.subscribe();
        self.spawn_source(key, hub, stream);
        Ok(receiver)
    }

    fn spawn_source<S>(&self, key: String, hub: Arc<SharedProxyHub>, stream: S)
    where
        S: Stream<Item = Result<Bytes>> + Send + 'static,
    {
        let registry = self.clone();
        tokio::spawn(async move {
            let mut stream = Box::pin(stream);
            let mut pending = Vec::with_capacity(BATCH_BYTES);
            loop {
                if hub.receiver_count() == 0 {
                    break;
                }
                match tokio::time::timeout(BATCH_FLUSH, stream.next()).await {
                    Ok(Some(Ok(bytes))) => {
                        pending.extend_from_slice(bytes.as_ref());
                        if pending.len() >= BATCH_BYTES {
                            hub.push(Bytes::from(std::mem::take(&mut pending)));
                            pending = Vec::with_capacity(BATCH_BYTES);
                        }
                    }
                    Ok(Some(Err(error))) => {
                        flush_pending(&hub, &mut pending);
                        warn!("Shared proxy stream {key} ended with error: {error}");
                        break;
                    }
                    Ok(None) => {
                        flush_pending(&hub, &mut pending);
                        break;
                    }
                    Err(_) => {
                        flush_pending(&hub, &mut pending);
                        pending = Vec::with_capacity(BATCH_BYTES);
                    }
                }
            }
            hub.close();
            if let Ok(mut hubs) = registry.inner.hubs.lock() {
                hubs.remove(&key);
            }
        });
    }
}

fn flush_pending(hub: &SharedProxyHub, pending: &mut Vec<u8>) {
    if !pending.is_empty() {
        hub.push(Bytes::from(std::mem::take(pending)));
    }
}

fn shared_udp_key(addr: &SocketAddrV4, if_name: Option<&str>, fcc: Option<&FccOptions>) -> String {
    let fcc_key = fcc
        .map(|value| {
            format!(
                "{}|{}|{}|{}",
                value.server,
                value.max_redirects,
                value.switch_extra_packets,
                value.switch_min_unicast_ms
            )
        })
        .unwrap_or_default();
    format!("udp|{}|{}|{}", if_name.unwrap_or(""), addr, fcc_key)
}

impl SharedProxyHub {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SharedProxyInner {
                chunks: VecDeque::with_capacity(BUFFER_CHUNKS),
                next_seq: 0,
                receivers: 0,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn subscribe(self: &Arc<Self>) -> SharedProxyReceiver {
        let next_seq = self
            .inner
            .lock()
            .map(|mut inner| {
                inner.receivers += 1;
                inner.next_seq
            })
            .unwrap_or(0);
        SharedProxyReceiver {
            hub: Arc::clone(self),
            next_seq,
        }
    }

    fn receiver_count(&self) -> usize {
        self.inner.lock().map(|inner| inner.receivers).unwrap_or(0)
    }

    fn push(&self, bytes: Bytes) {
        if let Ok(mut inner) = self.inner.lock() {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.chunks.push_back((seq, bytes));
            while inner.chunks.len() > BUFFER_CHUNKS {
                inner.chunks.pop_front();
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
        if let Ok(mut inner) = self.hub.inner.lock()
            && inner.receivers > 0
        {
            inner.receivers -= 1;
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

    #[actix_web::test]
    async fn new_subscriber_starts_at_live_edge() {
        let hub = Arc::new(SharedProxyHub::new());
        hub.push(Bytes::from_static(b"old"));
        let mut receiver = hub.subscribe();
        hub.push(Bytes::from_static(b"live"));

        assert_eq!(receiver.recv().await.unwrap(), Bytes::from_static(b"live"));
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
    fn key_changes_with_fcc_tuning() {
        let addr = SocketAddrV4::new("239.1.1.1".parse().unwrap(), 5000);
        let first = FccOptions {
            server: "10.0.0.1:8027".parse().unwrap(),
            max_redirects: 5,
            switch_extra_packets: 64,
            switch_min_unicast_ms: 500,
        };
        let mut second = first.clone();
        second.switch_min_unicast_ms = 750;

        assert_ne!(
            shared_udp_key(&addr, Some("iptv0"), Some(&first)),
            shared_udp_key(&addr, Some("iptv0"), Some(&second))
        );
    }
}
