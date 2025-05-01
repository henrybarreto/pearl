use std::{collections::HashMap, fmt::Debug, sync::Arc};

use async_trait::async_trait;

use tokio::sync::Mutex;

use log::{debug, trace};

use ssh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, CryptoVec,
};

#[derive(Debug, Clone)]
pub struct SSHHandler {
    pub clients: Arc<Mutex<HashMap<usize, (ChannelId, ssh::server::Handle)>>>,
    pub id: usize,
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
