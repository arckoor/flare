use aes_gcm_siv::{aead::Aead, AeadCore, Aes256GcmSiv, Key, KeyInit, Nonce};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use secstr::{SecStr, SecUtf8};
use serde::{Deserialize, Serializer};
use zeroize::Zeroize;

use crate::api::error::RestError;

pub fn deserialize_secstr<'de, D>(deserializer: D) -> Result<SecStr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecStr::from(s))
}

pub fn serialize_secstr<S>(value: &SecStr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&String::from_utf8_lossy(value.unsecure()))
}

pub fn deserialize_secutf8<'de, D>(deserializer: D) -> Result<SecUtf8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecUtf8::from(s))
}

pub struct PkceCipher {
    key: Key<Aes256GcmSiv>,
}

impl PkceCipher {
    pub fn new(key: &SecStr) -> Self {
        let mut key = BASE64_STANDARD.decode(key.unsecure()).unwrap();
        let mut slice = [0u8; 32];
        slice.copy_from_slice(&key);
        key.zeroize();
        let key: Key<Aes256GcmSiv> = slice.into();
        slice.zeroize();

        Self { key }
    }

    pub fn encrypt(&self, data: &[u8]) -> String {
        let cipher = Aes256GcmSiv::new(&self.key);
        let nonce = Aes256GcmSiv::generate_nonce(&mut aes_gcm_siv::aead::OsRng);
        let encrypted = cipher.encrypt(&nonce, data).unwrap();
        let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&encrypted);
        BASE64_STANDARD.encode(&result)
    }

    pub fn decrypt(&self, data: &str) -> Vec<u8> {
        let cipher = Aes256GcmSiv::new(&self.key);
        let data = BASE64_STANDARD.decode(data.as_bytes()).unwrap();
        let nonce = Nonce::from_slice(&data[..12]);
        let decrypted = cipher.decrypt(nonce, &data[12..]).unwrap();
        decrypted.to_vec()
    }
}

pub fn hash_password(password: &SecStr) -> Result<SecStr, RestError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = Argon2::default()
        .hash_password(password.unsecure(), &salt)
        .map_err(|_| RestError::internal("Failed to hash password"))?;
    Ok(SecStr::from(hash.serialize().to_string()))
}

pub fn verify_password(
    hash: String,
    password: &SecStr,
) -> Result<(), argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(&hash)?;
    Argon2::default().verify_password(password.unsecure(), &parsed_hash)?;
    Ok(())
}

#[cfg(not(feature = "sim"))]
pub mod mtls {
    use std::{fs::File, io::BufReader, path::Path, sync::Arc};

    use axum_server::tls_rustls::RustlsConfig;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
        RootCertStore, ServerConfig,
    };

    fn load_public_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .map(|c| c.unwrap())
            .collect::<Vec<CertificateDer>>();

        Ok(certs)
    }

    fn load_private_pem(path: &Path) -> Result<PrivateKeyDer<'static>, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .map(|k| k.unwrap())
            .next()
            .unwrap();

        Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key))
    }

    fn load_root_store(path: &Path) -> Result<RootCertStore, std::io::Error> {
        let ca_cert = load_public_pem(path).unwrap();
        let mut root_store = RootCertStore::empty();
        for cert in ca_cert {
            root_store.add(cert).unwrap();
        }

        Ok(root_store)
    }

    pub fn create_tls_config(path: &Path) -> RustlsConfig {
        let ca_path = path.join("ca.pem");
        let server_key_path = path.join("server-key.pem");
        let server_cert_path = path.join("server.pem");

        let root_store = load_root_store(&ca_path).unwrap();
        let private_key = load_private_pem(&server_key_path).unwrap();
        let certs = load_public_pem(&server_cert_path).unwrap();

        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .unwrap();

        RustlsConfig::from_config(Arc::new(
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, private_key)
                .expect("failed to build server config"),
        ))
    }
}
