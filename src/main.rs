use std::{
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display},
    io::Read,
    net::TcpStream,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;

use log::{debug, error, info, trace};
use serde_json::Value;
use ssh::{
    server::{Auth, Handler},
    Channel, ChannelId,
};

use ssh::{
    server::{Msg, Session},
    CryptoVec,
};

use ssh_key::rand_core::OsRng;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::Mutex,
    task, time,
};

use websocket::{
    client::IntoClientRequest, protocol::WebSocketConfig, stream::MaybeTlsStream, Bytes, Message,
    WebSocket,
};

mod errors;

struct WebSocketToSSHStream {
    pub stream: WebSocket<MaybeTlsStream<TcpStream>>,
    pub buffer: Option<Bytes>,
}

const SSH_PACKET_SIZE: usize = 4;

impl AsyncRead for WebSocketToSSHStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        trace!("reading from websocket to ssh");

        let this = &mut self.get_mut();

        if let Some(buffer) = this.buffer.take() {
            trace!("there is some data on buffer to be read to SSH");

            buf.put_slice(&buffer[SSH_PACKET_SIZE..]);

            return Poll::Ready(Ok(()));
        }

        if !this.stream.can_read() {
            trace!("cannot read the websocket now");

            return Poll::Pending;
        }

        let msg = this.stream.read();
        match msg {
            Ok(message) => match message {
                Message::Binary(data) => {
                    // NOTE: SSH's crate first reads 4 bytes, the size of the package, before read
                    // the whole packet. We notice this by reading remaining method from reading
                    // buffer.
                    if buf.remaining() == SSH_PACKET_SIZE {
                        trace!("SSH read specs package size");

                        debug!("read the SSH size package from websocket");
                        buf.put_slice(&data[..SSH_PACKET_SIZE]);

                        // NOTE: Put the remaining bytes in a buffer for futher reading.
                        this.buffer = Some(data);
                    } else {
                        debug!("read the SSH package to webscoket");

                        buf.put_slice(&data);
                    }

                    return Poll::Ready(Ok(()));
                }
                Message::Close(_) => return Poll::Ready(Ok(())),
                _ => return Poll::Ready(Ok(())),
            },
            Err(e) => {
                dbg!(&e);

                return Poll::Pending;
            }
        }
    }
}

impl AsyncWrite for WebSocketToSSHStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        trace!("WRITE");

        // from SSH to WEBSOCKET

        let this = &mut self.get_mut();

        if !this.stream.can_write() {
            return Poll::Pending;
        }

        let inner = &mut this.stream;

        dbg!(String::from_utf8_lossy(buf));

        let message = Message::binary(buf.to_vec()); // Properly frame it as a websocket binary message
        let _ = inner.send(message).unwrap(); // Use write_message instead of write

        return Poll::Ready(Ok(buf.len()));
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        trace!("FLUSH");

        // Pin::new(&mut self.get_mut().inner.get_mut()).poll_flush(cx)
        return Poll::Ready(Ok(()));
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        trace!("SHUTDOWN");

        return Poll::Ready(Ok(()));
        // Pin::new(&mut self.get_mut().inner.get_mut()).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub enum TunnelErrors {}

impl Display for TunnelErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!();
        // self.message.fmt(f)
    }
}

impl Error for TunnelErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

#[derive(Debug, Clone)]
/// Commands are types of control messages used inside the Tunnel's commands.
pub enum Commands {
    /// conn-ready control message's type.
    ConnReady,
    /// keep-alive control message's type.
    KeepAlive,
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
/// TUNNEL_ENDPOINT is the HTTP endpoint used to upgrade to the WebSocket connection that receives
/// controls messages from ShellHub's server.
///
/// NOTE: As ShellHub is starting to provide more than SSH access, this endpoint could be changed
/// to fit the new requirements.
pub const TUNNEL_ENDPOINT: &str = "/ssh/connection";

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
    pub async fn listen(&self) -> Result<(), impl Error> {
        let handler = MyHandler {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        // let (mut stream, _) = websocket_async::connect_async("ws://127.0.0.1:80/ssh/connection")
        let (mut stream, _) = websocket_async::connect_async(format!(
            "{}://{}:{}/ssh/connection",
            self.scheme, self.host, self.port
        ))
        .await
        .unwrap();

        let mut buffer = [0u8; 1024];

        loop {
            let handler = handler.clone();

            trace!("looping");

            let read = stream.get_mut().read(&mut buffer).await.unwrap();
            let b = &buffer[2..read - 1];

            let command_str = String::from_utf8_lossy(b);

            debug!("all command: {:?}", command_str);
            let parts: Vec<&str> = command_str.split("\n").map(|v| v).collect();

            debug!("first command: {:?}", parts[0]);

            if let Ok(json) = serde_json::from_str::<Value>(parts[0]) {
                trace!("converted");
                dbg!(&json);

                match Commands::from(json["command"].clone()) {
                    Commands::ConnReady => {
                        let tunnel = self.clone();
                        task::spawn(async move {
                            let conn_path = json["connPath"].as_str().unwrap_or_default();
                            info!("Connection ready on path: {}", conn_path);

                            let request = format!(
                                "{}://{}:{}{}",
                                tunnel.scheme, tunnel.host, tunnel.port, conn_path
                            )
                            .into_client_request()
                            .unwrap();

                            let websocket_config = Some(WebSocketConfig::default());

                            let (mut stream, _) = websocket::client::connect_with_config(
                                request,
                                websocket_config,
                                8,
                            )
                            .unwrap();

                            // NOTE: Read the GET request from websocket.
                            // /ssh/revdial?revdial.dialer=57df2c4e5200b17b6691eed26cd1229c

                            let mut buffer = [0 as u8; 256];
                            let _ = stream.get_mut().read(&mut buffer).unwrap();

                            debug!("{:?}", String::from_utf8_lossy(&buffer));

                            let adpter_stream = WebSocketToSSHStream {
                                stream,
                                buffer: None,
                            };

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

                            let session =
                                match ssh::server::run_stream(config, adpter_stream, handler).await
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
                trace!("not converted");

                return Err(errors::AgentError::new(
                    // TODO: Change it.
                    errors::AgentErrorKind::ErrorTunnel,
                    "Error on tunnel".to_string(),
                ));
            }
        } // <---
    }
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

#[derive(Debug)]
pub struct Config {
    pub tenant_id: String,
    pub server_address: String,
    pub private_key_path: String,
    pub hostname: Option<String>,
    pub identity: Option<String>,
}

#[derive(Debug)]
pub struct Agent {
    pub config: Config,
    pub tunnel: Tunnel,
}

unsafe impl Sync for Agent {}
unsafe impl Send for Agent {}

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

    pub async fn listen(&self) -> Result<(), errors::AgentError> {
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
        })?;*/

        self.tunnel.listen().await.unwrap();

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MyHandler {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, ssh::server::Handle)>>>,
    id: usize,
}

impl MyHandler {
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for (id, (channel, ref mut s)) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
}

#[async_trait]
impl Handler for MyHandler {
    type Error = ssh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("Session opened");

        {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.request_success();

        Ok(())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!("auth password");

        Ok(Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        dbg!(data);

        if data == [3] {
            return Err(ssh::Error::Disconnect);
        }

        let data = CryptoVec::from(format!(
            "Olá, pessoal, eu sou o Agent em Rust!: {}\r\n",
            String::from_utf8_lossy(data)
        ));
        self.post(data.clone()).await;
        session.data(channel, data);

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env("LOG").init();

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

        return;
    }

    info!("Agent initialized");

    info!("Listening to agent...");
    if let Err(_) = agent.listen().await {
        error!("Error listening to agent");

        return;
    }

    info!("Agent done");
}
