//! TLS material for the proxy: an ephemeral CA and a leaf certificate for
//! `127.0.0.1`/`localhost`, plus the rustls server config that terminates the
//! agent's connection. The CA (base64 PEM) goes into the brokered kubeconfig as
//! `certificate-authority-data`; the leaf, signed by the CA, is what the proxy
//! presents. ALPN offers both `h2` and `http/1.1` so client-go (h2) and HTTP/1.1
//! clients both negotiate.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use tokio_rustls::rustls::{
    self,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};

/// The proxy's generated TLS identity.
pub struct ProxyTls {
    ca_pem: String,
    server_config: Arc<ServerConfig>,
}

impl ProxyTls {
    /// Generate a fresh CA and a leaf for the loopback listener, and build the
    /// terminating server config. Called once at proxy startup.
    pub fn generate() -> Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };

        // Ephemeral CA (self-signed), the trust anchor the brokered kubeconfig pins.
        let ca_key = KeyPair::generate().context("generate CA key")?;
        let mut ca_params = CertificateParams::new(Vec::new()).context("CA params")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "guard kube-proxy CA");
        ca_params.distinguished_name = ca_dn;
        let ca_cert = ca_params.self_signed(&ca_key).context("self-sign CA")?;
        let ca_pem = ca_cert.pem();

        // Leaf for the loopback listener, signed by the CA, with SAN 127.0.0.1.
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().context("generate leaf key")?;
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).context("leaf params")?;
        leaf_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().context("dns san")?),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, "guard kube-proxy");
        leaf_params.distinguished_name = leaf_dn;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .context("sign leaf")?;

        let leaf_der = leaf_cert.der().clone();
        let ca_der = ca_cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("rustls protocol versions")?
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der, ca_der], key_der)
            .context("rustls server cert")?;
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            ca_pem,
            server_config: Arc::new(server_config),
        })
    }

    /// PEM of the CA certificate.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Base64 of the CA PEM, for the kubeconfig `certificate-authority-data`.
    pub fn ca_data_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.ca_pem.as_bytes())
    }

    /// The terminating server config (cert chain + ALPN).
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ca_and_server_config() {
        let tls = ProxyTls::generate().expect("generate TLS");
        assert!(tls.ca_pem().contains("BEGIN CERTIFICATE"));
        // CA data round-trips through base64 back to the PEM.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(tls.ca_data_b64())
            .unwrap();
        assert_eq!(decoded, tls.ca_pem().as_bytes());
        // ALPN advertises h2 and http/1.1, in that order.
        let cfg = tls.server_config();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn brokered_config_uses_generated_ca() {
        let tls = ProxyTls::generate().unwrap();
        let yaml = super::super::kubeconfig::brokered_kubeconfig(
            "https://127.0.0.1:8443",
            &tls.ca_data_b64(),
        );
        super::super::kubeconfig::validate_brokered_kubeconfig(&yaml).expect("valid brokered cfg");
    }
}
