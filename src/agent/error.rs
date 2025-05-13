use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum ErrorKind {
    ErrorDeviceGenerateIdentity,
    ErrorLoadDeviceInfo,
    ErrorGeneratePrivateKey,
    ErrorReadPublicKey,
    ErrorProbeServerInfo,
    ErrorAuthorize,
    ErroServerStartOverWebSocket,
    ErrorTunnel,
    ErrorUnauthorized,
    ErrorForbidden,
    ErrorUnknown,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Error { kind, message }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}
