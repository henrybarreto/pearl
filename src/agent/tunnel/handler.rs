use std::{collections::HashMap, fmt::Debug, sync::Arc};

use async_trait::async_trait;

use tracing::{debug, trace};

use ssh::{Channel, ChannelId, CryptoVec};

#[derive(Debug, Clone)]
pub struct Handler {}

impl Handler {}

#[async_trait]
impl ssh::server::Handler for Handler {
    type Error = ssh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<ssh::server::Msg>,
        session: &mut ssh::server::Session,
    ) -> Result<bool, Self::Error> {
        trace!("channel open handler called");

        println!("{:?}", channel.id());

        session.channel_success(channel.id()).unwrap();

        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ssh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ssh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<ssh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ssh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(ssh::Pty, u32)],
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        trace!("shell request handler called");

        session.request_success();

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        trace!("exec request handler called");

        session.request_success();

        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn auth_none(&mut self, user: &str) -> Result<ssh::server::Auth, Self::Error> {
        trace!("auth none was called");

        debug!("USER: {:?}", user);

        Ok(ssh::server::Auth::Accept)
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<ssh::server::Auth, Self::Error> {
        trace!("auth password called");

        debug!("USER: {:?}", user);
        debug!("PASSWORD: {:?}", password);

        Ok(ssh::server::Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<ssh::server::Auth, Self::Error> {
        Ok(ssh::server::Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        trace!("data handler called");

        if data == [3] {
            return Err(ssh::Error::Disconnect);
        }

        let data = CryptoVec::from(format!(
            "Olá, pessoal, eu sou o Agent em Rust!: {}\r\n",
            String::from_utf8_lossy(data)
        ));

        // self.post(data.clone()).await;

        session.data(channel, data).unwrap();

        Ok(())
    }
}
