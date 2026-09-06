//! Lightweight live-statistics poll for controllers without a WebSocket.
//!
//! API-key-only and cloud sessions cannot open the session WebSocket, so
//! nothing pushes `device:sync` frames and the dashboard would only move on
//! the (slow, heavy) full refresh. This task re-fetches just the per-device
//! statistics from the Integration API on `polling_interval_secs` and
//! updates `Device.stats` in place under one snapshot publish, which is a
//! handful of ~1 KB requests instead of the ~30-request, ~450 KB full pass.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::core_error::CoreError;
use crate::model::Device;

use super::{Controller, integration};

/// Background loop: poll device statistics every `interval_secs` until cancelled.
pub(in crate::controller) async fn stats_poll_task(
    controller: Controller,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = interval.tick() => {
                if let Err(error) = controller.poll_device_stats().await {
                    warn!(error = %error, "device statistics poll failed");
                }
            }
        }
    }
}

impl Controller {
    /// Refresh only `Device.stats` for every device already in the store.
    ///
    /// No-op when the Integration client or site is not available (e.g. a
    /// session-only connection), because the WebSocket covers that case.
    pub(crate) async fn poll_device_stats(&self) -> Result<(), CoreError> {
        let Some(integration) = self.inner.integration_client.lock().await.clone() else {
            return Ok(());
        };
        let Some(site_id) = *self.inner.site_id.lock().await else {
            return Ok(());
        };

        let store = &self.inner.store;
        let devices: Vec<Device> = store
            .devices_snapshot()
            .iter()
            .map(|device| Device::clone(device))
            .collect();
        if devices.is_empty() {
            return Ok(());
        }

        let count = devices.len();
        let updated = integration::fetch_device_statistics(integration, site_id, devices).await;

        // Same key/id convention as the WebSocket `device:sync` path.
        let batch = store.devices.begin_batch();
        for device in updated {
            let key = device.mac.as_str().to_owned();
            let id = device.id.clone();
            store.devices.upsert(key, id, device);
        }
        drop(batch);

        debug!(devices = count, "device statistics poll applied");
        Ok(())
    }
}
