//! Shutdown plumbing shared by the HTTP server and background workers.

use tokio::sync::broadcast;

#[derive(Clone)]
pub struct Shutdown {
    tx: broadcast::Sender<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<()>(1);
        Self { tx }
    }

    pub fn subscribe(&self) -> ShutdownGuard {
        ShutdownGuard {
            rx: self.tx.subscribe(),
        }
    }

    pub fn trigger(&self) {
        let _ = self.tx.send(());
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ShutdownGuard {
    rx: broadcast::Receiver<()>,
}

impl ShutdownGuard {
    pub async fn wait(&mut self) {
        let _ = self.rx.recv().await;
    }

    #[allow(dead_code)]
    pub fn is_triggered(&mut self) -> bool {
        matches!(
            self.rx.try_recv(),
            Ok(()) | Err(broadcast::error::TryRecvError::Closed)
        )
    }
}

pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = sigint.recv() => tracing::info!("Received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received Ctrl-C");
    }
}
