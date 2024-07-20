use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use russh_keys::key;
use ssh::server::{Msg, Session};
use ssh::*;
use tokio::sync::Mutex;
use websocket::{MaybeTlsStream, WebSocketStream};

use std::{
    fmt::Display,
    pin::Pin,
    task::{Context, Poll},
    time,
};

use ssh::{server::Handler, Error};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), ssh::server::Handle>>>,
    id: usize,
}

impl Server {
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for ((id, channel), ref mut s) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

#[async_trait]
impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        self.post(data.clone()).await;
        session.data(channel, data);
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        Ok(true)
    }
}

struct AdapterStream {
    pub stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl AsyncRead for AdapterStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for AdapterStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().stream.get_mut()).poll_write(cx, buf)
        // todo!();
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream.get_mut()).poll_flush(cx)
        // todo!();
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream.get_mut()).poll_shutdown(cx)
        // todo!();
    }
}

unsafe impl Send for AdapterStream {}

#[derive(Debug, Clone)]
pub struct ServerError {
    message: String,
}

impl From<Error> for ServerError {
    fn from(e: Error) -> Self {
        return ServerError {
            message: e.to_string(),
        };
    }
}

#[derive(Default)]
struct ServerHandler {}

impl ServerHandler {
    pub fn new() -> Self {
        return ServerHandler {};
    }
}

impl Handler for ServerHandler {
    type Error = ServerError;
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

/// The principal feature on the Agent server is the ability to provide an SSH server over
/// WebSocket, so, as proof of concept, this example shows it.
#[tokio::main]
async fn main() {
    println!("SSH over WebSocket");

    /*let tcp_stream = TcpStream::connect("localhost:8080").await.unwrap();

    let websocket_config = None;
    let websocket_role = websocket::tungstenite::protocol::Role::Client;

    let mut websocket_stream =
        websocket::WebSocketStream::from_raw_socket(tcp_stream, websocket_role, websocket_config)
            .await;*/

    let (websocket_stream, e) = websocket::connect_async("ws://localhost/ssh/connection")
        .await
        .unwrap();

    let ssh_config = ssh::server::Config {
        inactivity_timeout: Some(time::Duration::from_secs(3600)),
        auth_rejection_time: time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(time::Duration::from_secs(0)),
        ..Default::default()
    };

    let adapter_stream = AdapterStream {
        stream: websocket_stream,
    };

    let ssh_config = Arc::new(ssh_config);

    let session = ssh::server::run_stream(ssh_config, adapter_stream, ServerHandler::new())
        .await
        .unwrap();

    session.await.unwrap();
}
