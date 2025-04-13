use secstr::{SecStr, SecUtf8};
use serde::{Deserialize, Serializer};

pub fn deserialize_secstr_hex<'de, D>(deserializer: D) -> Result<SecStr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let bytes = botan::hex_decode(&s).map_err(serde::de::Error::custom)?;
    Ok(SecStr::from(bytes))
}

pub fn deserialize_secutf8<'de, D>(deserializer: D) -> Result<SecUtf8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecUtf8::from(s))
}

pub fn serialize_secutf8<S>(value: &SecUtf8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.unsecure())
}

pub struct PkceCipher {
    key: SecStr,
}

impl PkceCipher {
    const ALGO_NAME: &'static str = "AES-256/GCM";

    pub fn new(key: &SecStr) -> Self {
        Self { key: key.clone() }
    }

    pub fn encrypt(&self, data: &[u8]) -> String {
        let mut cipher =
            botan::Cipher::new(Self::ALGO_NAME, botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(self.key.unsecure()).unwrap();

        let nonce = botan::RandomNumberGenerator::new()
            .unwrap()
            .read(cipher.default_nonce_length())
            .unwrap();

        let encrypted = cipher.process(&nonce, data).unwrap();
        let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&encrypted);

        botan::hex_encode(&result).unwrap()
    }

    pub fn decrypt(&self, data: &str) -> Vec<u8> {
        let mut cipher =
            botan::Cipher::new(Self::ALGO_NAME, botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(self.key.unsecure()).unwrap();

        let data = botan::hex_decode(data).unwrap();
        let nonce = &data[..12];
        let decrypted = cipher.process(nonce, &data[12..]).unwrap();
        decrypted.to_vec()
    }
}

#[cfg(not(feature = "sim"))]
pub mod mtls {
    use std::{fs::File, io::BufReader, path::Path, sync::Arc};

    use axum_server::tls_rustls::RustlsConfig;
    use rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
        server::WebPkiClientVerifier,
    };

    fn load_public_pem(path: &Path) -> Vec<CertificateDer<'static>> {
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);
        CertificateDer::pem_reader_iter(&mut reader)
            .map(|c| c.unwrap())
            .collect::<Vec<CertificateDer>>()
    }

    fn load_private_pem(path: &Path) -> PrivateKeyDer<'static> {
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);
        let key = PrivatePkcs8KeyDer::pem_reader_iter(&mut reader)
            .map(|k| k.unwrap())
            .next()
            .unwrap();

        PrivateKeyDer::Pkcs8(key)
    }

    fn load_root_store(path: &Path) -> RootCertStore {
        let ca_cert = load_public_pem(path);
        let mut root_store = RootCertStore::empty();

        for cert in ca_cert.into_iter() {
            root_store.add(cert).unwrap();
        }

        root_store
    }

    pub fn create_tls_config(path: &Path) -> RustlsConfig {
        let ca_path = path.join("ca.pem");
        let server_key_path = path.join("server-key.pem");
        let server_cert_path = path.join("server.pem");

        let root_store = load_root_store(&ca_path);
        let private_key = load_private_pem(&server_key_path);
        let certs = load_public_pem(&server_cert_path);

        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .unwrap();

        RustlsConfig::from_config(Arc::new(
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, private_key)
                .unwrap(),
        ))
    }
}
