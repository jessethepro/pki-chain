use pki_chain::comm_protocol::{start_api_server, start_repair_server, start_setup_server};
use pki_chain::configs::AppConfig;
use pki_chain::storage::{get_state, StorageState};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    // Initialize logging
    let file_appender = tracing_appender::rolling::daily("logs", "pki_chain.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::try_new("info").unwrap()),
        )
        .with(
            tracing_subscriber::fmt::Layer::default()
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())),
        )
        .with(tracing_subscriber::fmt::Layer::default().with_writer(non_blocking))
        .init();
    // Load configuration
    let app_config = match AppConfig::load() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "Main -> Failed to load configuration");
            return;
        }
    };
    let mut storage_status = get_state(&app_config);
    while storage_status.error_message.is_none() {
        match storage_status.storage_state {
            StorageState::Ready => {
                tracing::info!(
                    "Main -> Storage is ready. Storage Status Results: {:?}",
                    storage_status
                );
                storage_status = start_api_server(&app_config, storage_status);
            }
            StorageState::Inconsistent => {
                tracing::warn!(
                    "Main -> Storage is inconsistent. Storage Status Results: {:?}",
                    storage_status
                );
                storage_status = start_repair_server(&app_config, storage_status);
            }
            StorageState::Empty => {
                tracing::warn!(
                    "Main -> Storage is empty. Storage Status Results: {:?}",
                    storage_status
                );
                start_setup_server(&app_config, storage_status);
                storage_status = get_state(&app_config);
            }
            _ => {
                tracing::warn!(
                    "Main -> Storage is in a setup state. Storage Status Results: {:?}",
                    storage_status
                );
            }
        }
    }
    tracing::error!(error = %storage_status.error_message.as_ref().unwrap(), "Main -> There are errors in the storage system");
    tracing::info!("Main -> Storage status: {:?}", storage_status);
}
