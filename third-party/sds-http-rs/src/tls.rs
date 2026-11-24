use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Build the hardened Post-Quantum crypto provider using `aws-lc-rs` ONLY.
/// Strictly restricts key exchange to `X25519MLKEM768` and cipher suites to TLS 1.3.
pub fn pq_crypto_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    Arc::new(provider)
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path)
        .map_err(|e| format!("failed to open certificate file '{}': {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certificate PEM '{}': {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in '{}'", path.display()));
    }
    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path)
        .map_err(|e| format!("failed to open private key file '{}': {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("failed to parse private key PEM '{}': {e}", path.display()))?
        .ok_or_else(|| format!("no private key found in '{}'", path.display()))
}

/// Mandatory client-certificate verifier for Sunshine GameStream mTLS.
///
/// Requires a non-empty syntactically valid end-entity certificate and cryptographically verifies
/// the TLS 1.3 `CertificateVerify` handshake signature, then delegates pairing trust policy to
/// Sunshine's post-handshake `verify` callback so denied clients still receive an explicit XML 401.
#[derive(Debug)]
pub struct SunshineClientCertVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl SunshineClientCertVerifier {
    pub fn new(algs: WebPkiSupportedAlgorithms) -> Self {
        Self { algs }
    }
}

impl ClientCertVerifier for SunshineClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if end_entity.as_ref().is_empty() {
            return Err(TlsError::NoCertificatesPresented);
        }
        // Validate X.509 DER structure and SPKI before allowing CertificateVerify signature check.
        let _ = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Server-certificate verifier for `SimpleWeb::Client<HTTPS>` when `verify_certificate == false`.
/// Still checks X.509 encoding and verifies TLS 1.3 `CertificateVerify` signatures.
#[derive(Debug)]
struct NoVerifyServerCertVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoVerifyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref().is_empty() {
            return Err(TlsError::NoCertificatesPresented);
        }
        let _ = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub fn build_server_config(
    cert_file: &Path,
    key_file: &Path,
    verify_file: Option<&Path>,
    require_client_cert: bool,
) -> Result<Arc<ServerConfig>, String> {
    let provider = pq_crypto_provider();
    let certs = load_certs(cert_file)?;
    let key = load_private_key(key_file)?;

    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("failed to configure TLS 1.3 protocol version: {e}"))?;

    let mut config = if let Some(ca_path) = verify_file {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(ca_path)? {
            roots
                .add(cert)
                .map_err(|e| format!("failed to add CA cert from '{}': {e}", ca_path.display()))?;
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| format!("failed to build client cert verifier: {e}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to configure server cert/key: {e}"))?
    } else if require_client_cert {
        let verifier = Arc::new(SunshineClientCertVerifier::new(
            provider.signature_verification_algorithms,
        ));
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to configure mTLS server cert/key: {e}"))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to configure TLS server cert/key: {e}"))?
    };

    // Disable TLS 1.3 session resumption/tickets so mTLS always performs full CertificateVerify
    // and populates peer_certificates() on every new connection.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;

    Ok(Arc::new(config))
}

/// Build the hardened TLS 1.3 Post-Quantum client configuration (`aws-lc-rs`, `X25519MLKEM768`).
///
/// When `verify_certificate == true` and `verify_file` is `None`, the client uses an empty
/// `RootCertStore` (failing closed rather than trusting ambient system CAs), enforcing
/// LAN-only explicit CA pinning.
pub fn build_client_config(
    verify_certificate: bool,
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
    verify_file: Option<&Path>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = pq_crypto_provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("failed to configure client TLS 1.3 protocol version: {e}"))?;

    let with_verifier = if verify_certificate {
        let mut roots = RootCertStore::empty();
        if let Some(ca_path) = verify_file {
            for cert in load_certs(ca_path)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("failed to add CA cert '{}': {e}", ca_path.display()))?;
            }
        }
        builder.with_root_certificates(roots)
    } else {
        let verifier = Arc::new(NoVerifyServerCertVerifier {
            algs: provider.signature_verification_algorithms,
        });
        builder.dangerous().with_custom_certificate_verifier(verifier)
    };

    let mut config = match (cert_file, key_file) {
        (Some(c), Some(k)) => {
            let certs = load_certs(c)?;
            let key = load_private_key(k)?;
            with_verifier
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("failed to configure client auth cert/key: {e}"))?
        }
        (None, None) => with_verifier.with_no_client_auth(),
        _ => {
            return Err(
                "client TLS auth requires both certification_file and private_key_file".into(),
            )
        }
    };

    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
