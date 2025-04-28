use std::{
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::StreamExt;

use serde::{Deserialize, Serialize};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::Mutex,
    task, time,
};

use log::{debug, error, info, trace};

use ssh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, CryptoVec, MethodSet,
};

use ssh_key::rand_core::OsRng;

use websocket::{
    client::IntoClientRequest,
    protocol::{
        frame::{
            coding::{Data, OpCode},
            Frame,
        },
        WebSocketConfig,
    },
    Bytes, Message,
};

use websocket_async::{MaybeTlsStream, WebSocketStream};

mod errors;

/// It is an adapter to convert websocket connection's messages into SSH packets to the SSH stream.
///
/// Essentially, it reads data from websocket, remove from the Message's packet and put back to the
/// SSH stream. It also does the same when the data goes out the SSH server, wrapping it into a
/// websocket binary message. Check the implementation for more details.
struct WebSocketToSSHStream {
    /// Internal websocket stream.
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Internal buffer to the remaining bytes of an SSH packet after reading the packet size.
    buffer: Option<Bytes>,
}

impl WebSocketToSSHStream {
    pub fn new(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        return WebSocketToSSHStream {
            stream,
            buffer: None,
        };
    }
}

impl AsyncRead for WebSocketToSSHStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        trace!("poll_read called on websocket to ssh adapter");

        // NOTE: It checks if there is a pending buffer to be written. If it does, remove the
        // buffer from structure, letting `None` on its place, and write it to SSH stream. Normally
        // it is called after the SSH packet size reading, to read the content of the packet.
        if let Some(buffer) = self.buffer.take() {
            trace!("there is some data on buffer to be read to SSH");

            dbg!(&buf.remaining());
            dbg!(&buffer);

            buf.put_slice(&buffer);

            return Poll::Ready(Ok(()));
        }

        return match self.stream.poll_next_unpin(cx) {
            Poll::Ready(option) => {
                trace!("poll ready on websocket read");

                // TODO: Remove `unwrap` calls.
                let p = option.unwrap();
                let msg = p.unwrap();

                match msg {
                    Message::Binary(buffer) => {
                        // NOTE: The SSH crate that we're using, cannot deal with a full WebSocket
                        // binary packet at once because it first reads four bytes, the SSH packet size,
                        // and, after that, the remaining, the size read. To address this issue, we
                        // check if the space on the buffer is less than the data inside the
                        // message, sending only the required piece and storing the remaining to
                        // the next read in a buffer on the adapter structure.
                        if buf.remaining() < buffer.len() {
                            // WARN: The `remaining` is a variable because after put the data into
                            // the slice, its value goes to zero, messing up with the remaining
                            // part put on structure's buffer.
                            let remaining = buf.remaining();

                            dbg!(remaining);
                            dbg!(String::from_utf8_lossy(&buffer[..remaining]));

                            buf.put_slice(&buffer[..remaining]);

                            self.buffer = Some(buffer.slice(remaining..));
                        } else {
                            buf.put_slice(&buffer);
                        }
                    }
                    // TODO: Deal better with all cases of messages.
                    Message::Close(e) => {
                        println!("{:?}", e.unwrap());
                    }
                    _ => panic!("other message than binary"),
                }

                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                trace!("poll pending on websocket read");

                Poll::Pending
            }
        };
    }
}

impl AsyncWrite for WebSocketToSSHStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        trace!("WRITE");

        let mut frame = Frame::message(buf.to_vec(), OpCode::Data(Data::Binary), true);
        // WARN: Avoid "bad mask" error when creating the frame.
        // TODO: Create the mask the right way.
        frame.header_mut().mask = Some([1, 2, 3, 4]);

        let mut serialized = Vec::new();

        // NOTE: After creating the frame, we put it into a slice to be written into the websocket
        // connection.
        frame.format(&mut serialized).unwrap();

        // NOTE: After converting the SSH packet into a websocket frame, we write it to the
        // websocket connection, confirming the size of the SSH packet to caller, not what was
        // written on websocket connection, as it greater than the SSH packet.
        return match Pin::new(&mut self.get_mut().stream.get_mut()).poll_write(cx, &serialized) {
            Poll::Ready(_) => Poll::Ready(Ok(buf.len())),
            Poll::Pending => {
                trace!("poll pending on websocket write");

                Poll::Pending
            }
        };
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        trace!("FLUSH");

        Pin::new(&mut self.get_mut().stream.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        trace!("SHUTDOWN");

        Pin::new(&mut self.get_mut().stream.get_mut()).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub enum TunnelErrors {}

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

                                        let adapter_stream = WebSocketToSSHStream::new(stream);

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

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    /// `info` is optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<DeviceInfo>,

    /// omit if `None`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<String>>,

    /// embed all fields from `DeviceAuth` at the same level
    #[serde(flatten)]
    pub device_auth: DeviceAuth,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuth {
    /// hostname is optional if `identity` is present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// identity is optional if `hostname` is present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<DeviceIdentity>,

    /// always required
    #[serde(rename = "public_key")]
    pub public_key: String,

    /// always required
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    pub uid: String,
    pub token: String,
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,

    #[serde(rename = "pretty_name")]
    pub pretty_name: String,

    pub version: String,
    pub arch: String,
    pub platform: String,
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
    pub token: Option<String>,
}

unsafe impl Sync for Agent {}
unsafe impl Send for Agent {}

impl Agent {
    fn new(config: Config) -> Self {
        Agent {
            config,
            tunnel: Tunnel::new(),
            token: None,
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

    /*

    type DeviceAuthRequest struct {
        Info     *DeviceInfo `json:"info"`
        Sessions []string    `json:"sessions,omitempty"`
        *DeviceAuth
    }

    type DeviceAuthResponse struct {
        UID       string `json:"uid"`
        Token     string `json:"token"`
        Name      string `json:"name"`
        Namespace string `json:"namespace"`
    }

    */

    async fn authorize(&mut self) -> Result<(), &dyn Error> {
        // POST http://localhost/api/devices/auth

        let req = DeviceAuthRequest {
            info: Some(DeviceInfo {
                id: "device-1234".into(),
                pretty_name: "Thermostat Living Room".into(),
                version: "1.2.0".into(),
                arch: "armv7".into(),
                platform: "linux".into(),
            }),
            sessions: None,
            device_auth: DeviceAuth {
                hostname: None,
                identity: Some(DeviceIdentity { mac: "123".into() }),
                public_key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...".into(),
                tenant_id: "00000000-0000-4000-0000-000000000000".into(),
            },
        };

        let client = http::Client::new();
        let resp = client
            .post("http://localhost/api/devices/auth")
            .json(&req)
            .send()
            .await
            .unwrap();

        dbg!(resp.status());
        if !resp.status().is_success() {}

        let auth_data: DeviceAuthResponse = resp.json().await.unwrap();

        self.token = Some(auth_data.token.clone());

        dbg!(auth_data);

        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), errors::AgentError> {
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

        if let Err(_) = self.authorize().await {
            error!("Error authorizing device");

            return Err(errors::AgentError::new(
                errors::AgentErrorKind::ErrorAuthorize,
                "Error authorizing device".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<(), errors::AgentError> {
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

        self.tunnel.listen(self.token.take().unwrap()).await;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SSHHandler {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, ssh::server::Handle)>>>,
    id: usize,
}

impl SSHHandler {
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
impl Handler for SSHHandler {
    type Error = ssh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        trace!("channel open handler called");

        println!("{:?}", channel.id());

        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!("shell request handler called");

        session.request_success();

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        trace!("auth none was called");

        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        trace!("auth password called");

        debug!("USER: {:?}", user);
        debug!("PASSWORD: {:?}", password);

        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("data handler called");

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
    let mut agent = Agent::new(Config {
        tenant_id: "00000000-0000-4000-0000-000000000000".to_string(),
        server_address: "http://localhost:80".to_string(),
        private_key_path: "/tmp/shellhub".to_string(),
        hostname: None,
        identity: None,
    });

    info!("ShellHub Peal Agent version: {}", env!("CARGO_PKG_VERSION"));

    info!("Server address: {}", agent.config.server_address);
    info!("Namespace tenant's : {}", agent.config.tenant_id);

    info!("Initializing agent...");
    if let Err(_) = agent.init().await {
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
