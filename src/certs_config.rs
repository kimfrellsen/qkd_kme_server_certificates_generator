use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CertsConfig {
    pub(crate) cert_exp_time_days: usize,
    pub(crate) ca_cert_exp_time_days: usize,
    pub(crate) certs_dir: String,
    pub(crate) kmes: Vec<KmeConfig>
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmeConfig {
    pub(crate) id: i64,
    pub(crate) addr_for_saes: String,
    pub(crate) addr_for_kmes: String,
    pub(crate) saes: Vec<SaeConfig>
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SaeConfig {
    pub(crate) id: i64,
    pub(crate) client_certificate_serial: Vec<u8>,
    pub(crate) client_pfx_certificate_password: String
}