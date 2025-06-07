use std::fmt::Debug;
use tokio::process::Command;

use async_trait::async_trait;

use ssh::{Channel, ChannelId, CryptoVec};

use tracing::{debug, error, info};

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
        info!("channel open handler called");

        session.channel_success(channel.id()).unwrap();

        println!("{:?}", channel.id());

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
        info!("channel open direct tcpip handler called");

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
        info!("channel open forwarded handler called");

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
        info!("pty request handler called");

        session.channel_failure(channel)?;
        session.close(channel)?;

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        info!("shell request handler called");

        session.channel_failure(channel)?;
        session.close(channel)?;

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        info!("exec request handler called");

        session.channel_success(channel)?;

        let command = String::from_utf8_lossy(data).to_string();
        info!(command = command, "command to execute");

        let command_parts: Vec<&str> = command.split(' ').collect();

        let result_result = Command::new(command_parts[0])
            .args(&command_parts[1..])
            .output()
            .await;

        let result = match result_result {
            Ok(result) => result,
            Err(e) => {
                error!(error = e.to_string(), "failed to execute the command");

                let data = CryptoVec::from(e.to_string());
                session.data(channel, data)?;
                session.exit_status_request(channel, 1)?;

                session.eof(channel)?;
                session.close(channel)?;

                return Ok(());
            }
        };

        let mut stdout = result.stdout;
        let mut stderr = result.stderr;

        let mut output: Vec<u8> = Vec::new();
        output.append(&mut stdout);
        output.append(&mut stderr);

        let status = result.status.code().unwrap();
        info!(status = status, "command exit status");

        let data = CryptoVec::from(output);
        session.data(channel, data)?;

        session.exit_status_request(channel, status as u32)?;

        session.eof(channel)?;
        session.close(channel)?;

        info!("command executed with success");

        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        info!("subsystem request handler called");

        session.channel_failure(channel)?;
        session.close(channel)?;

        Ok(())
    }

    async fn auth_none(&mut self, user: &str) -> Result<ssh::server::Auth, Self::Error> {
        info!("auth none was called");

        Ok(ssh::server::Auth::Accept)
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<ssh::server::Auth, Self::Error> {
        info!("auth password called");

        debug!("USER: {:?}", user);
        debug!("PASSWORD: {:?}", password);

        Ok(ssh::server::Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<ssh::server::Auth, Self::Error> {
        info!("auth publickey called");

        Ok(ssh::server::Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ssh::server::Session,
    ) -> Result<(), Self::Error> {
        info!("data handler called");

        session.eof(channel)?;
        session.close(channel)?;

        // if data == [3] {
        //     return Err(ssh::Error::Disconnect);
        // }

        // let msg = format!("{}\r\n", String::from_utf8_lossy(data));
        // let stdin = self.stdin.clone().unwrap();
        // let data = CryptoVec::from();

        // self.post(data.clone()).await;

        // session.data(channel, data).unwrap();

        Ok(())
    }
}
