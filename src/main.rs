pub mod agent;

use agent::{
    config::{Config, Identity},
    Agent,
};

use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_env_var("LOG")
                .with_default_directive(LevelFilter::INFO.into())
                .from_env()
                .unwrap(),
        )
        .init();

    info!("Starting ShellHub agent...");
    let mut agent = Agent::new(Config {
        tenant_id: "00000000-0000-4000-0000-000000000000".to_string(),
        server_address: "http://localhost:80".to_string(),
        private_key_path: "/tmp/shellhub".to_string(),
        hostname: None,
        identity: Identity {
            mac: "aa:bb:cc:dd:ee:ff".into(),
        },
    });

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "ShellHub Pearl Agent version"
    );

    info!(
        server_address = agent.config.server_address,
        "Server address",
    );

    info!(tenant_id = agent.config.tenant_id, "Namespace tenant's");

    info!("Initializing agent...");
    if let Err(e) = agent.init().await {
        error!("Error initializing agent: {}", e);

        return;
    }

    info!("Agent initialized");

    info!("Listening to agent...");
    // TODO: If agent's listening fails due to authentication expiration, network problems or
    // server is down, we should retry after a reauthentication or after a while. If the error is
    // not recoverable, we should exit the program.
    if let Err(error) = agent.listen().await {
        error!("Error listening to agent: {}", error);

        return;
    }

    info!("Agent done");
}
