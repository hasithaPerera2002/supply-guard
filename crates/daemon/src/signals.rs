use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn setup_shutdown_handler(shutdown_tx: broadcast::Sender<()>) -> anyhow::Result<()> {
    let mut sigterm = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT])?;
    
    std::thread::spawn(move || {
        for sig in sigterm.forever() {
            info!("Received signal {:?}, initiating graceful shutdown...", sig);
            SHUTDOWN.store(true, Ordering::SeqCst);
            let _ = shutdown_tx.send(());
            break;
        }
    });

    Ok(())
}

pub fn should_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}
