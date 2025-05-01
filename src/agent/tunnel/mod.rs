pub mod adapter;
pub mod handler;

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display},
    sync::Arc,
};

use futures::StreamExt;

use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task, time};

use log::{debug, error, info, trace};

use ssh_key::rand_core::OsRng;

use websocket::{client::IntoClientRequest, protocol::WebSocketConfig, Message};

use adapter::Adapter;
use handler::SSHHandler;

/// TUNNEL_ENDPOINT is the HTTP endpoint used to upgrade to the WebSocket connection that receives
/// controls messages from ShellHub's server.
///
/// NOTE: As ShellHub is starting to provide more than SSH access, this endpoint could be changed
/// to fit the new requirements.
pub const TUNNEL_ENDPOINT: &str = "/ssh/connection";

#[derive(Debug, Clone)]
/// Commands are types of control messages used inside the Tunnel's commands.
pub enum Commands {
    /// conn-ready control message's type.
    ConnReady,
    /// keep-alive control message's type.
    KeepAlive,
    /// Unknown control message.
    Unknown,
}

impl From<String> for Commands {
    fn from(value: String) -> Self {
        // NOTE: Avoid calling "as_str" here.
        match value.as_str() {
            "conn-ready" => {
                return Commands::ConnReady;
            }
            "keep-alive" => {
                return Commands::KeepAlive;
            }
            _ => {
                return Commands::Unknown;
            }
        }
    }
}

impl From<serde_json::Value> for Commands {
    fn from(value: serde_json::Value) -> Self {
        match value.as_str() {
            Some("conn-ready") => {
                return Commands::ConnReady;
            }
            Some("keep-alive") => {
                return Commands::KeepAlive;
            }
            _ => {
                return Commands::Unknown;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Scheme {
    WS,
    WSS,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::WS => write!(f, "ws"),
            Scheme::WSS => write!(f, "wss"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    #[serde(rename = "command")]
    pub command: String,
    #[serde(rename = "connPath")]
    pub conn_path: String,
}

// TODO: Implement Default
impl Tunnel {
    pub fn new() -> Self {
        // TODO: Validate server address. Checks if it has "ws" or "wss" as protocol security
        // indication, if the address is an IP or domain name, and the port. If the port isn't
        // defined, use the "ws" or "wss" for port.
        Tunnel {
            scheme: Scheme::WS,
            host: String::from("127.0.0.1"),
            port: 80,
        }
    }

    pub fn connect_handler(&self, callback: &dyn Fn()) -> Result<(), &dyn Error> {
        callback();

        Ok(())
    }

    pub fn keep_alive_handler(&self, callback: &dyn Fn()) -> Result<(), &dyn Error> {
        callback();

        Ok(())
    }

    pub fn close_handler(&self, callback: &dyn Fn()) -> Result<(), &dyn Error> {
        callback();

        Ok(())
    }

    /// Listens for the incoming SSH connections coming from WebSocket connection.
    pub async fn listen(&self, token: String) {
        let handler = SSHHandler {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let mut request = format!(
            "{}://{}:{}/ssh/connection",
            self.scheme, self.host, self.port
        )
        .into_client_request()
        .unwrap();

        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );

        let (mut stream, _) = websocket_async::connect_async(request).await.unwrap();

        loop {
            trace!("looping");

            while let Some(data) = stream.next().await {
                let handler = handler.clone();

                let msg = data.unwrap();
                dbg!(&msg);

                match msg {
                    Message::Binary(bytes) => {
                        if let Ok(control) = serde_json::from_slice::<Control>(&bytes) {
                            match Commands::from(control.command) {
                                Commands::ConnReady => {
                                    let tunnel = self.clone();

                                    task::spawn(async move {
                                        let conn_path = control.conn_path;
                                        info!("Connection ready on path: {}", conn_path);

                                        let request = format!(
                                            "{}://{}:{}{}",
                                            tunnel.scheme, tunnel.host, tunnel.port, conn_path
                                        )
                                        .into_client_request()
                                        .unwrap();

                                        let websocket_config = Some(WebSocketConfig::default());

                                        let (stream, _) =
                                            websocket_async::connect_async_with_config(
                                                request,
                                                websocket_config,
                                                true,
                                            )
                                            .await
                                            .unwrap();

                                        // NOTE: Read the GET request from websocket.
                                        // /ssh/revdial?revdial.dialer=57df2c4e5200b17b6691eed26cd1229c&uuid=00000000-0000-4000-0000-000000000000
                                        //
                                        // let mut buffer = [0 as u8; 256];
                                        // let read =
                                        //     stream.get_mut().read(&mut buffer).await.unwrap();

                                        // dbg!(String::from_utf8_lossy(&buffer[..read]));

                                        let adapter_stream = Adapter::new(stream);

                                        let config = ssh::server::Config {
                                            inactivity_timeout: Some(time::Duration::from_secs(
                                                3600,
                                            )),
                                            keys: vec![ssh::keys::PrivateKey::random(
                                                &mut OsRng,
                                                ssh::keys::Algorithm::Ed25519,
                                            )
                                            .unwrap()],
                                            ..Default::default()
                                        };

                                        let config = Arc::new(config);

                                        info!("session started");

                                        let session = match ssh::server::run_stream(
                                            config,
                                            adapter_stream,
                                            handler,
                                        )
                                        .await
                                        {
                                            Ok(s) => s,
                                            Err(e) => {
                                                dbg!(e);

                                                debug!("Connection setup failed");

                                                return;
                                            }
                                        };

                                        match session.await {
                                            Ok(_) => debug!("Connection closed"),
                                            Err(e) => {
                                                dbg!(e);

                                                debug!("Connection closed with error");
                                            }
                                        }

                                        info!("session done");
                                    });
                                }
                                Commands::KeepAlive => {
                                    info!("Received keep-alive");
                                }
                                Commands::Unknown => {
                                    error!("Unknown command format");
                                }
                            }
                        } else {
                            trace!("not JSON converted");

                            // return Err(errors::AgentError::new(
                            //     // TODO: Change it.
                            //     errors::AgentErrorKind::ErrorTunnel,
                            //     "Error on tunnel".to_string(),
                            // ));
                        }
                    }
                    Message::Close(option) => {
                        let frame = option.unwrap();

                        error!("{:?}", frame);
                    }
                    _ => {
                        trace!("invalid message");
                    }
                }

                continue;
            }
        }
    }
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}
