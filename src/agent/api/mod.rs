use std::{error, fmt::Display};

use serde::{Deserialize, Serialize};

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
pub struct DeviceAuthRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<DeviceInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<String>>,

    #[serde(flatten)]
    pub device_auth: DeviceAuth,
}

/// The DeviceIdentity struct represents the identity of a device. It contains the MAC address of
/// the network interface of used to connect to the ShellHub server. If the interface doesn't have
/// a MAC address, the case of virtual interfaces, the user should define a custom identity using
/// the environmental variable SHELLHUB_IDENTITY.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// The MAC address of the network interface used to connect to the ShellHub server.
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuth {
    /// The device's hostname.
    ///
    /// This field is optional and can be omitted if the device doesn't have a hostname or if the
    /// user prefers to use the default hostname. The hostname is a "friendly" name that can be
    /// used to identify the device in the ShellHub server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// The device's identity.
    pub identity: DeviceIdentity,

    /// The device's public key.
    #[serde(rename = "public_key")]
    pub public_key: String,

    /// The device's namespace tenant ID.
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    /// The device's unique identifier.
    pub uid: String,
    /// The device's name.
    pub name: String,
    /// The device's namespace.
    pub namespace: String,
    /// The device's authentication token.
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub message: String,
    pub code: Option<u16>,
}

impl Error {
    pub fn new(message: String, code: Option<u16>) -> Self {
        Error { message, code }
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

/// API is a struct that represents the HTTP client used to communicate with the ShellHub server.
/// It contains methods for sending requests and receiving responses from the server.
#[derive(Debug)]
pub struct API {
    /// client is the HTTP client used to send requests to the ShellHub server.
    client: http::Client,
}

impl API {
    pub fn new() -> Self {
        API {
            client: http::Client::new(),
        }
    }

    /// health_check sends a GET request to the ShellHub server to check if it is reachable.
    pub async fn health_check(&self) -> Result<(), Error> {
        let resp = match self.client.get("http://localhost/info").send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(Error::new(format!("Failed to send request: {}", e), None));
            }
        };

        if !resp.status().is_success() {
            return Err(Error::new(
                "ShellHub server is not reachable".to_string(),
                Some(resp.status().into()),
            ));
        }

        Ok(())
    }

    /// authenticate sends a POST request to the ShellHub server to authenticate a device.
    pub async fn authenticate(&self, req: DeviceAuthRequest) -> Result<DeviceAuthResponse, Error> {
        let resp = match self
            .client
            .post("http://localhost/api/devices/auth")
            .json(&req)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Err(Error::new(format!("Failed to send request: {}", e), None));
            }
        };

        if !resp.status().is_success() {
            return Err(Error::new(
                "Failed to authenticate device".to_string(),
                Some(resp.status().into()),
            ));
        }

        let auth_data: DeviceAuthResponse = resp.json().await.unwrap();
        

        Ok(auth_data)
    }
}
