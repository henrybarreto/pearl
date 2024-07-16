use std::{error::Error, fmt::Display};

#[derive(Debug, Clone)]
pub enum AgentErrorKind {
    ErrorDeviceGenerateIdentity,
    ErrorLoadDeviceInfo,
    ErrorGeneratePrivateKey,
    ErrorReadPublicKey,
    ErrorProbeServerInfo,
    ErrorAuthorize,
    ErroServerStartOverWebSocket,
}

#[derive(Debug, Clone)]
pub struct AgentError {
    kind: AgentErrorKind,
    message: String,
}

impl AgentError {
    pub fn new(kind: AgentErrorKind, message: String) -> Self {
        AgentError { kind, message }
    }
}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl Error for AgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}
