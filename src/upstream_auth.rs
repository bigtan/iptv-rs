use crate::{args::EffectiveArgs, iptv::get_channel_list_raw};
use anyhow::Result;
use log::info;
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

#[derive(Default)]
pub(crate) struct UpstreamAuthManager {
    status: Mutex<AuthStatus>,
    refresh_gate: AsyncMutex<()>,
}

impl UpstreamAuthManager {
    pub(crate) fn mark_success(&self) {
        if let Ok(mut status) = self.status.lock() {
            status.last_success = Some(Instant::now());
            status.last_error = None;
        }
    }

    pub(crate) fn is_fresh(&self, max_age: Duration) -> bool {
        self.status
            .lock()
            .ok()
            .and_then(|status| status.last_success)
            .is_some_and(|last_success| last_success.elapsed() < max_age)
    }

    pub(crate) async fn ensure_fresh(&self, args: &EffectiveArgs) -> Result<()> {
        if self.is_fresh(AUTH_MAX_AGE) {
            return Ok(());
        }
        self.refresh(args, false).await
    }

    pub(crate) async fn force_refresh(&self, args: &EffectiveArgs) -> Result<()> {
        self.refresh(args, true).await
    }

    async fn refresh(&self, args: &EffectiveArgs, force: bool) -> Result<()> {
        let _guard = self.refresh_gate.lock().await;
        if !force && self.is_fresh(AUTH_MAX_AGE) {
            return Ok(());
        }

        info!("Refreshing upstream IPTV authorization");
        match get_channel_list_raw(args).await {
            Ok(_) => {
                self.mark_success();
                info!("Upstream IPTV authorization refreshed");
                Ok(())
            }
            Err(error) => {
                if let Ok(mut status) = self.status.lock() {
                    status.last_error = Some(error.to_string());
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_authentication_is_fresh() {
        let manager = UpstreamAuthManager::default();
        assert!(!manager.is_fresh(AUTH_MAX_AGE));
        manager.mark_success();
        assert!(manager.is_fresh(AUTH_MAX_AGE));
    }
}
