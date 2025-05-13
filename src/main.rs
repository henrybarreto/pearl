pub mod agent;

use agent::{config::Config, Agent};
use log::{error, info};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env("LOG").init();

    info!("Starting ShellHub agent...");
    let mut agent = Agent::new(Config {
        tenant_id: "00000000-0000-4000-0000-000000000000".to_string(),
        server_address: "http://localhost:80".to_string(),
        private_key_path: "/tmp/shellhub".to_string(),
        hostname: None,
        identity: None,
    });

    info!(
        "ShellHub Pearl Agent version: {}",
        env!("CARGO_PKG_VERSION")
    );

    info!("Server address: {}", agent.config.server_address);
    info!("Namespace tenant's : {}", agent.config.tenant_id);

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
