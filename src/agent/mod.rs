pub mod config;
pub mod tunnel;

use std::{error::Error, fmt::Debug};

use config::Config;

use serde::{Deserialize, Serialize};

use log::{error, info};

use tunnel::Tunnel;

use crate::errors;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    pub uid: String,
    pub token: String,
    pub name: String,
    pub namespace: String,
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

#[derive(Debug)]
pub struct Agent {
    pub config: Config,
    pub tunnel: Tunnel,
    pub token: Option<String>,
}

unsafe impl Sync for Agent {}
unsafe impl Send for Agent {}

impl Agent {
    pub fn new(config: Config) -> Self {
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
