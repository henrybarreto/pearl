pub mod api;
pub mod config;
pub mod error;
pub mod tunnel;

use std::{error::Error, fmt::Debug, time::Duration};

use api::API;
use config::Config;

use tracing::{error, info};

use tokio::time::sleep;
use tunnel::Tunnel;

#[derive(Debug)]
pub struct Agent {
    pub config: Config,
    pub tunnel: Tunnel,
    pub api: API,
    pub token: Option<String>,
}

unsafe impl Sync for Agent {}
unsafe impl Send for Agent {}

impl Agent {
    pub fn new(config: Config) -> Self {
        Agent {
            config,
            tunnel: Tunnel::new(),
            api: API::new(),
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

    async fn authorize(&mut self) -> Result<(), error::Error> {
        let req = api::DeviceAuthRequest {
            info: Some(api::DeviceInfo {
                id: "device-1234".into(),
                pretty_name: "Thermostat".into(),
                version: "1.2.0".into(),
                arch: "armv7".into(),
                platform: "linux".into(),
            }),
            sessions: None,
            device_auth: api::DeviceAuth {
                hostname: self.config.hostname.clone(),
                identity: self.config.identity.clone().into(),
                public_key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...".into(),
                tenant_id: self.config.tenant_id.clone(),
            },
        };

        let auth_data: api::DeviceAuthResponse = match self.api.authenticate(req).await {
            Ok(auth_data) => auth_data,
            Err(error) => match error.code {
                Some(code) => match code {
                    401 => {
                        return Err(error::Error::new(
                            error::ErrorKind::ErrorUnauthorized,
                            format!("Unauthorized: {}", error),
                        ));
                    }
                    403 => {
                        return Err(error::Error::new(
                            error::ErrorKind::ErrorForbidden,
                            format!("Forbidden: {}", error),
                        ));
                    }
                    _ => {
                        return Err(error::Error::new(
                            error::ErrorKind::ErrorUnknown,
                            format!("Unknown error: {}", error),
                        ));
                    }
                },
                None => {
                    return Err(error::Error::new(
                        error::ErrorKind::ErrorAuthorize,
                        format!("Error authorizing device: {}", error),
                    ));
                }
            },
        };

        self.token = Some(auth_data.token);

        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), error::Error> {
        info!("Initializing...");

        if let Err(_) = self.generate_device_identity() {
            error!("Error generating device identity");

            return Err(error::Error::new(
                error::ErrorKind::ErrorDeviceGenerateIdentity,
                "Error generating device identity".to_string(),
            ));
        }

        if let Err(_) = self.load_device_info() {
            error!("Error loading device info");

            return Err(error::Error::new(
                error::ErrorKind::ErrorLoadDeviceInfo,
                "Error loading device info".to_string(),
            ));
        }

        if let Err(_) = self.generate_private_key() {
            error!("Error generating private key");

            return Err(error::Error::new(
                error::ErrorKind::ErrorGeneratePrivateKey,
                "Error generating private key".to_string(),
            ));
        }

        if let Err(_) = self.read_public_key() {
            error!("Error reading public key");

            return Err(error::Error::new(
                error::ErrorKind::ErrorReadPublicKey,
                "Error reading public key".to_string(),
            ));
        }

        if let Err(_) = self.probe_server_info() {
            error!("Error probing server info");

            return Err(error::Error::new(
                error::ErrorKind::ErrorProbeServerInfo,
                "Error probing server info".to_string(),
            ));
        }

        if let Err(e) = self.authorize().await {
            error!("Error authorizing device");

            return Err(error::Error::new(
                error::ErrorKind::ErrorAuthorize,
                format!("Error authorizing device: {}", e),
            ));
        }

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<(), error::Error> {
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
        info!("Listening to agent...");

        loop {
            info!("Tunnel listing started");

            if self.token.is_none() {
                error!("Token is None");

                if let Err(e) = self.authorize().await {
                    match e.kind {
                        error::ErrorKind::ErrorUnauthorized => {
                            error!("Unauthorized: {}", e);

                            info!("Retrying authorization...");

                            // NOTE: Wait 10 seconds before retrying authentication.
                            sleep(Duration::from_secs(10)).await;

                            continue;
                        }
                        error::ErrorKind::ErrorForbidden => {
                            error!("Forbidden: {}", e);

                            break;
                        }
                        _ => {
                            error!("Unknown error: {}", e);

                            break;
                        }
                    }
                }
            }

            let token = self.token.take().unwrap();

            if let Err(error) = self.tunnel.listen(token).await {
                if !error.fatal {
                    info!("Retrying connection to server...");

                    continue;
                }

                error!("Error listening to agent: {}", error);

                break;
            }

            info!("Tunnel listen done");
        }

        Ok(())
    }
}
