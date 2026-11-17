use crate::{
    args::{EffectiveArgs, UpstreamCredentials},
    iptv::{DEFAULT_EDS_URL, build_client_with_if, discover_base_url, get_channel_list_raw},
};
use anyhow::Result;
use log::info;
use reqwest::Client;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

pub(crate) const AUTH_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
pub(crate) const AUTH_MAX_AGE: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Default)]
struct AuthStatus {
    last_success: Option<Instant>,
    last_error: Option<String>,
}

struct CachedEndpoint {
    interface: Option<String>,
    user: String,
    client: Client,
    base_url: Option<String>,
}

pub(crate) struct UpstreamAuthManager {
    eds_url: String,
    status: Mutex<AuthStatus>,
    endpoint: Mutex<Option<CachedEndpoint>>,
    endpoint_gate: AsyncMutex<()>,
    refresh_gate: AsyncMutex<()>,
}

impl Default for UpstreamAuthManager {
    fn default() -> Self {
        Self::with_eds_url(DEFAULT_EDS_URL.to_string())
    }
}

impl UpstreamAuthManager {
    pub(crate) fn with_eds_url(eds_url: String) -> Self {
        Self {
            eds_url,
            status: Mutex::new(AuthStatus::default()),
            endpoint: Mutex::new(None),
            endpoint_gate: AsyncMutex::new(()),
            refresh_gate: AsyncMutex::new(()),
        }
    }

    pub(crate) fn mark_success(&self) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.last_success = Some(Instant::now());
        status.last_error = None;
    }

    pub(crate) fn is_fresh(&self, max_age: Duration) -> bool {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_success
            .is_some_and(|last_success| last_success.elapsed() < max_age)
    }

    pub(crate) fn invalidate_endpoint(&self) {
        *self.endpoint.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub(crate) fn on_config_change(&self, previous: &EffectiveArgs, next: &EffectiveArgs) {
        if previous.interface != next.interface || previous.upstream != next.upstream {
            self.invalidate_endpoint();
            let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
            status.last_success = None;
            status.last_error = None;
        }
    }

    pub(crate) async fn resolve_session(
        &self,
        creds: &UpstreamCredentials,
        interface: Option<&str>,
    ) -> Result<(Client, String)> {
        if let Some(ready) = self.peek_session(&creds.user, interface) {
            return Ok(ready);
        }

        let _guard = self.endpoint_gate.lock().await;
        if let Some(ready) = self.peek_session(&creds.user, interface) {
            return Ok(ready);
        }

        let client = {
            let mut slot = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = slot.as_ref()
                && existing.interface.as_deref() == interface
                && existing.user == creds.user
            {
                existing.client.clone()
            } else {
                let built = build_client_with_if(interface)?;
                *slot = Some(CachedEndpoint {
                    interface: interface.map(str::to_owned),
                    user: creds.user.clone(),
                    client: built.clone(),
                    base_url: None,
                });
                built
            }
        };

        let base_url = match discover_base_url(&client, &self.eds_url, &creds.user).await {
            Ok(base_url) => base_url,
            Err(error) => {
                self.invalidate_endpoint();
                return Err(error);
            }
        };

        {
            let mut slot = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = slot.as_mut()
                && existing.interface.as_deref() == interface
                && existing.user == creds.user
            {
                existing.base_url = Some(base_url.clone());
            }
        }

        Ok((client, base_url))
    }

    fn peek_session(&self, user: &str, interface: Option<&str>) -> Option<(Client, String)> {
        let slot = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        let entry = slot.as_ref()?;
        if entry.interface.as_deref() == interface
            && entry.user == user
            && let Some(base_url) = entry.base_url.as_ref()
        {
            return Some((entry.client.clone(), base_url.clone()));
        }
        None
    }

    pub(crate) async fn ensure_fresh(&self, args: &EffectiveArgs) -> Result<()> {
        let Some(creds) = args.upstream.as_ref() else {
            return Ok(());
        };
        if self.is_fresh(AUTH_MAX_AGE) {
            return Ok(());
        }
        self.refresh(creds, args.interface.as_deref(), false).await
    }

    pub(crate) async fn force_refresh(&self, args: &EffectiveArgs) -> Result<()> {
        let Some(creds) = args.upstream.as_ref() else {
            return Ok(());
        };
        self.refresh(creds, args.interface.as_deref(), true).await
    }

    async fn refresh(
        &self,
        creds: &UpstreamCredentials,
        interface: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let _guard = self.refresh_gate.lock().await;
        if !force && self.is_fresh(AUTH_MAX_AGE) {
            return Ok(());
        }

        info!("Refreshing upstream IPTV authorization");
        match get_channel_list_raw(self, creds, interface).await {
            Ok(_) => {
                self.mark_success();
                info!("Upstream IPTV authorization refreshed");
                Ok(())
            }
            Err(error) => {
                let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
                status.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn successful_authentication_is_fresh() {
        let manager = UpstreamAuthManager::default();
        assert!(!manager.is_fresh(AUTH_MAX_AGE));
        manager.mark_success();
        assert!(manager.is_fresh(AUTH_MAX_AGE));
    }

    #[tokio::test]
    async fn reuses_client_and_base_url_until_invalidated_or_user_changes() {
        let eds_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let eds_addr = eds_listener.local_addr().unwrap();
        let eds_hits = Arc::new(AtomicUsize::new(0));
        let eds_hits_srv = eds_hits.clone();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = eds_listener.accept().await {
                eds_hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = r#"{"epgurl":"http://127.0.0.1:18080/EPG/jsp/index.jsp"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let manager = UpstreamAuthManager::with_eds_url(format!(
            "http://{eds_addr}/EDS/jsp/AuthenticationURL"
        ));
        let creds_a = UpstreamCredentials {
            user: "user-a".to_string(),
            passwd: "pw".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            imei: String::new(),
            address: String::new(),
        };

        let (_, url1) = manager.resolve_session(&creds_a, None).await.unwrap();
        let (_, url2) = manager.resolve_session(&creds_a, None).await.unwrap();
        assert_eq!(url1, "http://127.0.0.1:18080");
        assert_eq!(url2, "http://127.0.0.1:18080");
        assert_eq!(
            eds_hits.load(Ordering::SeqCst),
            1,
            "second lookup must reuse cached base_url without querying EDS"
        );

        // Changing user must re-discover base_url.
        let mut creds_b = creds_a.clone();
        creds_b.user = "user-b".to_string();
        let _ = manager.resolve_session(&creds_b, None).await.unwrap();
        assert_eq!(eds_hits.load(Ordering::SeqCst), 2);

        // Explicit invalidation on upstream error forces re-discovery on next request.
        manager.invalidate_endpoint();
        let _ = manager.resolve_session(&creds_b, None).await.unwrap();
        assert_eq!(eds_hits.load(Ordering::SeqCst), 3);
    }
}
