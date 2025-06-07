#[derive(Debug, Clone)]
pub struct Identity {
    pub mac: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub tenant_id: String,
    pub server_address: String,
    pub private_key_path: String,
    pub hostname: Option<String>,
    pub identity: Identity,
}
