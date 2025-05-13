pub mod adapter;
pub mod handler;

use std::{
    collections::HashMap,
    error::{self},
    fmt::{Debug, Display},
    sync::Arc,
};

use futures::StreamExt;

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, sync::Mutex, task, time};

use tracing::{debug, error, info, trace};

use ssh_key::rand_core::OsRng;

use websocket::{client::IntoClientRequest, protocol::WebSocketConfig, Message};

use adapter::Adapter;
use handler::Handler;

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

#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    pub fatal: bool,
}

impl Error {
    pub fn new(message: String, fatal: bool) -> Self {
        Error { message, fatal }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        self.source()
    }
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

    pub fn connect_handler(&self, callback: &dyn Fn()) -> Result<(), Error> {
        callback();

        Ok(())
    }

    pub fn keep_alive_handler(&self, callback: &dyn Fn()) -> Result<(), Error> {
        callback();

        Ok(())
    }

    pub fn close_handler(&self, callback: &dyn Fn()) -> Result<(), Error> {
        callback();

        Ok(())
    }

    /// Listens for the incoming SSH connections coming from WebSocket connection.
    pub async fn listen(&self, token: String) -> Result<(), Error> {
        trace!("listen started");

        let handler = Handler {};

        // NOTE: The self object, Tunnel, implements Display that generate the server full address
        // based on the information on the Tunnel.
        let mut request = format!("{}/ssh/connection", self)
            .into_client_request()
            .unwrap();

        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );

        debug!(token = token, "authentication token");

        let (mut stream, _) = match websocket_async::connect_async(request).await {
            Ok((stream, response)) => {
                info!("Connected to server");

                (stream, response)
            }
            Err(e) => {
                error!("Error connecting to server: {}", e);

                return Err(Error::new(
                    format!("Error connecting to server: {}", e),
                    false,
                ));
            }
        };

        loop {
            trace!("looping");

            while let Some(data) = stream.next().await {
                let handler = handler.clone();

                let msg = match data {
                    Ok(m) => m,
                    Err(e) => {
                        error!("{:?}", e);

                        break;
                    }
                };

                match msg {
                    Message::Binary(bytes) => {
                        let control = match serde_json::from_slice::<Control>(&bytes) {
                            Ok(c) => c,
                            Err(_) => {
                                trace!("not JSON converted");

                                continue;
                            }
                        };

                        match Commands::from(control.command) {
                            Commands::ConnReady => {
                                let tunnel = self.clone();

                                task::spawn(async move {
                                    let conn_path = control.conn_path;
                                    debug!(conn_path = conn_path, "connection ready on path");

                                    let request = format!(
                                        "{}://{}:{}{}",
                                        tunnel.scheme, tunnel.host, tunnel.port, conn_path
                                    )
                                    .into_client_request()
                                    .unwrap();

                                    let websocket_config = Some(WebSocketConfig::default());

                                    let (stream, _) = websocket_async::connect_async_with_config(
                                        request,
                                        websocket_config,
                                        true,
                                    )
                                    .await
                                    .unwrap();

                                    // NOTE: Read the GET request from websocket.
                                    // /ssh/revdial?revdial.dialer=57df2c4e5200b17b6691eed26cd1229c&uuid=00000000-0000-4000-0000-000000000000

                                    // let mut buffer = [0 as u8; 256];
                                    // let read =
                                    //     stream.get_mut().read(&mut buffer).await.unwrap();

                                    //

                                    let adapter_stream = Adapter::new(stream);

                                    let config = ssh::server::Config {
                                        inactivity_timeout: Some(time::Duration::from_secs(3600)),
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
                                            debug!("connection setup failed: {}", e);

                                            return;
                                        }
                                    };

                                    match session.await {
                                        Ok(_) => debug!("connection closed"),
                                        Err(e) => {
                                            debug!("connection closed with error: {}", e);
                                        }
                                    }

                                    info!("session done");
                                });
                            }
                            Commands::KeepAlive => {
                                info!("received keep-alive");
                            }
                            Commands::Unknown => {
                                error!("unknown command format");
                            }
                        }
                    }
                    Message::Close(option) => {
                        let frame = option.unwrap();

                        error!("{:?}", frame);

                        break;
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
