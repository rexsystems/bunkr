//! Realtime fan-out to connected devices. Events carry no content, only hints
//! ("channel 3 has new entries"); clients then fetch ciphertext over HTTP.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bunkr_proto::{DeviceId, ServerWs};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Default)]
pub struct Hub {
    inner: Arc<Mutex<HashMap<DeviceId, Vec<(u64, UnboundedSender<ServerWs>)>>>>,
    next: Arc<std::sync::atomic::AtomicU64>,
}

impl Hub {
    pub fn register(&self, device: DeviceId, tx: UnboundedSender<ServerWs>) -> u64 {
        let id = self
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .lock()
            .unwrap()
            .entry(device)
            .or_default()
            .push((id, tx));
        id
    }

    pub fn unregister(&self, device: DeviceId, id: u64) {
        let mut m = self.inner.lock().unwrap();
        if let Some(v) = m.get_mut(&device) {
            v.retain(|(i, _)| *i != id);
            if v.is_empty() {
                m.remove(&device);
            }
        }
    }

    pub fn send(&self, device: DeviceId, ev: ServerWs) {
        if let Some(v) = self.inner.lock().unwrap().get(&device) {
            for (_, tx) in v {
                let _ = tx.send(ev.clone());
            }
        }
    }

    pub fn send_many(&self, devices: &[DeviceId], ev: ServerWs) {
        let m = self.inner.lock().unwrap();
        for d in devices {
            if let Some(v) = m.get(d) {
                for (_, tx) in v {
                    let _ = tx.send(ev.clone());
                }
            }
        }
    }

    pub fn broadcast(&self, ev: ServerWs) {
        for v in self.inner.lock().unwrap().values() {
            for (_, tx) in v {
                let _ = tx.send(ev.clone());
            }
        }
    }

    pub fn any_online(&self, devices: &[DeviceId]) -> bool {
        let m = self.inner.lock().unwrap();
        devices.iter().any(|d| m.contains_key(d))
    }

    /// Kill a device's live sockets.
    pub fn revoke(&self, device: DeviceId) {
        let v = self.inner.lock().unwrap().remove(&device);
        for (_, tx) in v.into_iter().flatten() {
            let _ = tx.send(ServerWs::Revoked);
        }
    }
}
