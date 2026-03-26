use pki_chain::configs::AppConfig;
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
            tracing::error!(error = %e, "Failed to load configuration");
            return;
        }
    };
    // Initialize storage based on its current state
    match pki_chain::storage::get_storage_state(&app_config.clone()) {
        Ok(pki_chain::storage::StorageState::NotFound)
        | Ok(pki_chain::storage::StorageState::Empty) => {
            tracing::info!("Storage not ready. Initializing storage...");
            match pki_chain::storage::get_storage_empty(app_config.clone()) {
                Ok(storage) => {
                    storage.create_storage().initialize_storage();
                    tracing::info!("Storage initialized successfully.");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open empty storage");
                }
            }
        }
        Ok(pki_chain::storage::StorageState::Created) => {
            tracing::info!("Storage created but not initialized. Initializing storage...");
            match pki_chain::storage::get_storage_created(app_config.clone()) {
                Ok(storage) => {
                    storage.initialize_storage();
                    tracing::info!("Storage initialized successfully.");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open created storage");
                }
            }
        }

        Ok(pki_chain::storage::StorageState::Initialized) => {
            tracing::info!("Existing storage found and initialized. Starting socket server for adding first admin.");
        }
        Ok(pki_chain::storage::StorageState::Ready) => {
            tracing::info!("Storage is ready.");
        }
        Ok(pki_chain::storage::StorageState::Inconsistent) => {
            tracing::error!("Storage is in an inconsistent state. Please check the storage and resolve any issues before restarting the application.");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get storage state");
            return;
        }
    }
    pki_chain::comm_protocol::start_comm_server(app_config);
}
