use std::{
    borrow::Borrow,
    error::Error,
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time,
};

use log::{error, info};
use ssh::server::Handler;

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use websocket::MaybeTlsStream;

mod errors;

#[derive(Debug)]
pub struct Config {
    pub tenant_id: String,
    pub server_address: String,
    pub private_key_path: String,
    pub hostname: Option<String>,
    pub identity: Option<String>,
}

struct AdapterStream {
    pub inner: websocket::WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl AsyncRead for AdapterStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for AdapterStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut()).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct Tunnel;

impl Tunnel {
    pub fn new() -> Self {
        Tunnel {}
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
    pub async fn listen(&self, handler: impl Handler + Send + 'static) -> Result<(), impl Error> {
        let (stream, _) = websocket::connect_async("ws://127.0.0.1:80/ssh/connection")
            .await
            .unwrap();

        let config = ssh::server::Config {
            inactivity_timeout: Some(time::Duration::from_secs(3600)),
            auth_rejection_time: time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(time::Duration::from_secs(0)),
            ..Default::default()
        };

        let config = Arc::new(config);

        let adapter_stream = AdapterStream { inner: stream };

        let session = ssh::server::run_stream(config, adapter_stream, handler).await;
        if session.is_err() {
            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorAuthorize,
                "Error authorizing device".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Agent {
    pub config: Config,
    pub tunnel: Tunnel,
}

unsafe impl Sync for Agent {}
unsafe impl Send for Agent {}

macro_rules! go {
    ($name:ident, $body:block) => {
        std::thread::spawn(move || $body);
    };
}

impl Agent {
    fn new(config: Config) -> Self {
        Agent {
            config,
            tunnel: Tunnel::new(),
        }
    }

    fn generate_device_identity(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    fn load_device_info(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    fn generate_private_key(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    fn read_public_key(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    fn probe_server_info(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    fn authorize(&self) -> Result<(), &dyn Error> {
        Ok(())
    }

    pub fn init(&self) -> Result<(), errors::AgentError> {
        info!("Initializing...");

        if let Err(_) = self.generate_device_identity() {
            error!("Error generating device identity");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorDeviceGenerateIdentity,
                "Error generating device identity".to_string(),
            ));
        }

        if let Err(_) = self.load_device_info() {
            error!("Error loading device info");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorLoadDeviceInfo,
                "Error loading device info".to_string(),
            ));
        }

        if let Err(_) = self.generate_private_key() {
            error!("Error generating private key");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorGeneratePrivateKey,
                "Error generating private key".to_string(),
            ));
        }

        if let Err(_) = self.read_public_key() {
            error!("Error reading public key");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorReadPublicKey,
                "Error reading public key".to_string(),
            ));
        }

        if let Err(_) = self.probe_server_info() {
            error!("Error probing server info");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorProbeServerInfo,
                "Error probing server info".to_string(),
            ));
        }

        if let Err(_) = self.authorize() {
            error!("Error authorizing device");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorAuthorize,
                "Error authorizing device".to_string(),
            ));
        }

        Ok(())
    }

    pub fn listen(&self) -> Result<(), errors::AgentError> {
        /*let (lister_sender, lister_receiver) = std::sync::mpsc::channel::<bool>();

        let agent = self.clone();
        go!(agent, {
            loop {
                lister_receiver.recv().unwrap();

                info!("Pinging server...");
                if let Err(_) = agent.ping() {
                    error!("Error pinging server");
                }

                info!("Server pinged");
            }
        });

        lister_sender.send(true).unwrap();

        self.tunnel.connect_handler(&|| {
            info!("Connected to server");
        })?;

        self.tunnel.keep_alive_handler(&|| {
            info!("Keep alive");
        })?;

        self.tunnel.close_handler(&|| {
            info!("Connection closed");
        })?;

        self.tunnel.listen()?;*/

        Ok(())
    }
}

fn main() {
    info!("Starting ShellHub agent...");
    let agent = Agent::new(Config {
        tenant_id: "09db1455-c643-495e-9775-ff1633343448".to_string(),
        server_address: "http://localhost:80".to_string(),
        private_key_path: "/tmp/shellhub".to_string(),
        hostname: None,
        identity: None,
    });

    info!("ShellHub Peal Agent version: {}", env!("CARGO_PKG_VERSION"));

    info!("Server address: {}", agent.config.server_address);
    info!("Namespace tenant's : {}", agent.config.tenant_id);

    info!("Initializing agent...");
    if let Err(_) = agent.init() {
        error!("Error initializing agent");
    }

    info!("Agent initialized");

    info!("Listening to agent...");
    if let Err(_) = agent.listen() {
        error!("Error listening to agent");
    }

    info!("Agent done");
}
