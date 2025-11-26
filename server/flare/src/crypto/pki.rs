use std::{
    fmt::Display,
    io::{BufReader, Cursor},
    path::Path,
    sync::Arc,
    time::Duration,
};

use axum_server::tls_rustls::RustlsConfig;
use botan::{CertificateBuilder, RandomNumberGenerator};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
    version,
};
use secstr::SecUtf8;

use crate::{
    api::error::RestError,
    crypto::HASH_ALGORITHM,
    time::{ONE_MINUTE, ONE_YEAR, now},
};

pub struct Key {
    key: botan::Privkey,
}

impl Key {
    const KEY_EXT: &str = "key";

    pub fn new<S>(
        path: &Path,
        name: S,
        algo: &str,
        write: bool,
        kek: Option<&SecUtf8>,
    ) -> Result<Self, RestError>
    where
        S: std::fmt::Display,
    {
        let path = path.join(format!("{name}.{}", Self::KEY_EXT));
        if std::fs::exists(&path)? {
            Self::load(&path, kek)
        } else {
            Self::generate(&path, algo, write, kek)
        }
    }

    fn generate(
        path: &Path,
        algo: &str,
        write: bool,
        kek: Option<&SecUtf8>,
    ) -> Result<Self, RestError> {
        let mut rng = botan::RandomNumberGenerator::new_system()?;
        let key = botan::Privkey::create(algo, "", &mut rng)?;
        if write {
            if let Some(kek) = kek {
                std::fs::write(path, key.pem_encode_encrypted(kek.unsecure(), &mut rng)?)?;
            } else {
                std::fs::write(path, key.pem_encode()?)?;
            }
        }
        Ok(Self { key })
    }

    fn load(path: &Path, kek: Option<&SecUtf8>) -> Result<Self, RestError> {
        let pem = std::fs::read_to_string(path)?;
        let key = if let Some(kek) = kek {
            botan::Privkey::load_encrypted_pem(&pem, kek.unsecure())?
        } else {
            botan::Privkey::load_pem(&pem)?
        };
        Ok(Self { key })
    }

    pub fn public_key(&self) -> Result<botan::Pubkey, RestError> {
        Ok(self.key.pubkey()?)
    }

    pub fn private_pem(&self) -> Result<String, RestError> {
        Ok(self.key.pem_encode()?)
    }

    pub fn public_pem(&self) -> Result<String, RestError> {
        Ok(self.public_key()?.pem_encode()?)
    }
}

#[derive(PartialEq, Eq)]
enum CertificateType {
    Ca,
    Server,
    Proxy,
}

impl Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CertificateType::Ca => "ca",
            CertificateType::Server => "server",
            CertificateType::Proxy => "proxy",
        })
    }
}

pub struct Certificate {
    key: Key,
    cert: botan::Certificate,
    kind: CertificateType,
}

impl Certificate {
    const ALGO_NAME: &str = "Ed25519";
    const CERT_EXT: &str = "cert";

    fn new(
        path: &Path,
        kind: CertificateType,
        kek: Option<&SecUtf8>,
        ca: Option<&Certificate>,
    ) -> Result<Self, RestError> {
        let cert_path = path.join(format!("{kind}.{}", Self::CERT_EXT));
        let cert = if std::fs::exists(&cert_path)? {
            Self::load(path, &cert_path, kind, kek)
        } else {
            Self::generate(path, &cert_path, kind, kek, ca)
        }?;

        cert.validate(ca)?;
        Ok(cert)
    }

    fn load(
        base: &Path,
        cert_path: &Path,
        kind: CertificateType,
        kek: Option<&SecUtf8>,
    ) -> Result<Self, RestError> {
        let key = Key::new(
            base,
            &kind,
            Self::ALGO_NAME,
            kind != CertificateType::Ca,
            kek,
        )?;
        let cert = botan::Certificate::load(
            std::fs::read_to_string(cert_path)
                .expect("Certificate must be present")
                .as_bytes(),
        )?;

        Ok(Self { cert, key, kind })
    }

    fn generate(
        base: &Path,
        cert_path: &Path,
        kind: CertificateType,
        kek: Option<&SecUtf8>,
        ca: Option<&Certificate>,
    ) -> Result<Self, RestError> {
        let mut rng = RandomNumberGenerator::new_system()?;

        let now = now();
        let not_before = (now - Duration::from_secs_f64(ONE_MINUTE * 10.0)).as_secs();
        let not_after = (now + Duration::from_secs_f64(ONE_YEAR)).as_secs();

        let key = Key::new(
            base,
            &kind,
            Self::ALGO_NAME,
            kind != CertificateType::Ca,
            kek,
        )?;
        let mut builder = CertificateBuilder::new()?;
        builder.add_common_name(&format!("flare {kind}"))?;
        builder.add_organization("flare")?;

        let cert = match kind {
            CertificateType::Ca => {
                builder.set_as_ca_certificate(Some(1))?;
                builder
                    .into_self_signed(&key.key, &mut rng, not_before, not_after, None, None, None)?
            }
            CertificateType::Server | CertificateType::Proxy => {
                builder.add_constraints(&[botan::CertUsage::DigitalSignature])?;

                let ca = ca.expect("A CA is required to sign certificates");

                match kind {
                    CertificateType::Ca => unreachable!(),
                    CertificateType::Server => {
                        builder.add_ex_constraint(&botan::OID::from_str("PKIX.ServerAuth")?)?
                    }
                    CertificateType::Proxy => {
                        builder.add_ex_constraint(&botan::OID::from_str("PKIX.ClientAuth")?)?
                    }
                }

                let req = builder.into_request(&key.key, &mut rng, None, None, None)?;
                req.sign(
                    &ca.cert,
                    &ca.key.key,
                    &mut rng,
                    not_before,
                    not_after,
                    None,
                    None,
                    None,
                )?
            }
        };

        std::fs::write(cert_path, cert.to_pem()?)?;

        Ok(Self { cert, key, kind })
    }

    fn validate(&self, ca: Option<&Certificate>) -> Result<(), RestError> {
        if self.kind != CertificateType::Ca {
            assert_eq!(
                self.cert.public_key()?.fingerprint(HASH_ALGORITHM)?,
                self.key.public_key()?.fingerprint(HASH_ALGORITHM)?,
                "Key must match the certificate!"
            );
        }

        if let Some(ca) = ca {
            assert!(
                self.cert
                    .verify(&[], &[&ca.cert], None, None, None)?
                    .success(),
                "{}",
                format!("Certificate ({}) must be signed by CA", self.kind)
            );
        }

        Ok(())
    }

    pub fn save_cert_at(&self, path: &Path) -> Result<(), RestError> {
        let path = path.join(format!("{}.{}", self.kind, Self::CERT_EXT));
        if !std::fs::exists(&path)? {
            std::fs::write(path, self.cert.to_pem()?)?
        }
        Ok(())
    }

    pub fn to_cert_der(&self) -> Result<CertificateDer<'static>, RestError> {
        let mut reader = BufReader::new(Cursor::new(self.cert.to_pem()?));
        Ok(CertificateDer::pem_reader_iter(&mut reader)
            .map(|c| c.unwrap())
            .next()
            .unwrap())
    }

    pub fn to_key_der(&self) -> Result<PrivateKeyDer<'static>, RestError> {
        let mut reader = BufReader::new(Cursor::new(self.key.private_pem()?));
        Ok(PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::pem_reader_iter(&mut reader)
                .map(|k| k.unwrap())
                .next()
                .unwrap(),
        ))
    }

    pub fn to_root_store(&self) -> Result<RootCertStore, RestError> {
        let der = self.to_cert_der()?;
        let mut root_store = RootCertStore::empty();
        root_store.add(der).unwrap();
        Ok(root_store)
    }
}

fn create_certificates<'a>(
    internal: &Path,
    external: &Path,
    kek: SecUtf8,
) -> Result<(RootCertStore, PrivateKeyDer<'a>, CertificateDer<'a>), RestError> {
    let ca = Certificate::new(internal, CertificateType::Ca, None, None)?;
    let server = Certificate::new(internal, CertificateType::Server, Some(&kek), Some(&ca))?;
    // proxy cert needs to be generated too
    let _ = Certificate::new(external, CertificateType::Proxy, None, Some(&ca))?;
    ca.save_cert_at(external)?;

    let root_store = ca.to_root_store()?;
    let private_key = server.to_key_der()?;
    let cert = server.to_cert_der()?;

    Ok((root_store, private_key, cert))
}

pub fn mtls_config(
    internal: &Path,
    external: &Path,
    kek: SecUtf8,
) -> Result<RustlsConfig, RestError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install TLS provider");

    let (root_store, private_key, cert) = create_certificates(internal, external, kek)?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    Ok(RustlsConfig::from_config(Arc::new(
        ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], private_key)
            .unwrap(),
    )))
}

#[cfg(test)]
mod tests {
    use secstr::SecUtf8;
    use tempfile::TempDir;

    use crate::crypto::pki::{Certificate, Key, create_certificates, mtls_config};

    #[test]
    fn test_key_generation() {
        let t = TempDir::new().unwrap();
        let key = Key::new(t.path(), "test-key", "Ed25519", true, None).unwrap();
        assert!(std::fs::exists(t.path().join("test-key.key")).unwrap());
        assert!(
            std::fs::read_to_string(t.path().join("test-key.key"))
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        let key2 = Key::new(t.path(), "test-key", "Ed25519", true, None).unwrap();
        assert_eq!(key.public_pem().unwrap(), key2.public_pem().unwrap());
        assert_eq!(key.private_pem().unwrap(), key2.private_pem().unwrap());

        // not written to disk
        let _ = Key::new(t.path(), "test-key-2", "Ed25519", false, None).unwrap();
        assert!(!std::fs::exists(t.path().join("test-key-2.key")).unwrap());

        let _ = Key::new(
            t.path(),
            "test-key-3",
            "Ed25519",
            true,
            Some(&SecUtf8::from("12345")),
        )
        .unwrap();
        assert!(std::fs::exists(t.path().join("test-key-3.key")).unwrap());
        assert!(
            std::fs::read_to_string(t.path().join("test-key-3.key"))
                .unwrap()
                .starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        );
        // wrong KEK
        assert!(
            Key::new(
                t.path(),
                "test-key-3",
                "Ed25519",
                true,
                Some(&SecUtf8::from("45678")),
            )
            .is_err()
        );
    }

    #[test]
    fn test_cert_generation() {
        let t = TempDir::new().unwrap();
        let t2 = TempDir::new().unwrap();

        let ca = Certificate::new(t.path(), super::CertificateType::Ca, None, None).unwrap();

        assert!(std::fs::exists(t.path().join("ca.cert")).unwrap());
        assert!(!std::fs::exists(t.path().join("ca.key")).unwrap());
        assert!(
            std::fs::read_to_string(t.path().join("ca.cert"))
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        let ca_2 = Certificate::new(t.path(), super::CertificateType::Ca, None, None).unwrap();
        assert_eq!(ca.cert.to_pem().unwrap(), ca_2.cert.to_pem().unwrap());

        let cert =
            Certificate::new(t.path(), super::CertificateType::Server, None, Some(&ca)).unwrap();
        assert!(std::fs::exists(t.path().join("server.cert")).unwrap());
        assert!(std::fs::exists(t.path().join("server.key")).unwrap());
        assert!(!std::fs::exists(t2.path().join("server.cert")).unwrap());
        cert.save_cert_at(t2.path()).unwrap();
        assert!(std::fs::exists(t2.path().join("server.cert")).unwrap());
        let cert_2 =
            Certificate::new(t.path(), super::CertificateType::Server, None, Some(&ca)).unwrap();
        assert_eq!(cert_2.cert.to_pem().unwrap(), cert_2.cert.to_pem().unwrap());

        let internal = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();

        assert!(
            create_certificates(internal.path(), external.path(), SecUtf8::from("12345")).is_ok()
        );
        for path in [
            internal.path().join("ca.cert"),
            internal.path().join("server.cert"),
            internal.path().join("server.key"),
            external.path().join("ca.cert"),
            external.path().join("proxy.cert"),
            external.path().join("proxy.key"),
        ] {
            assert!(std::fs::exists(path).unwrap());
        }
        assert_eq!(
            std::fs::read_to_string(internal.path().join("ca.cert")).unwrap(),
            std::fs::read_to_string(external.path().join("ca.cert")).unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn test_wrong_ca() {
        let internal = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        assert!(
            create_certificates(internal.path(), external.path(), SecUtf8::from("12345")).is_ok()
        );

        // new proxy cert will be signed with a new (different) CA
        std::fs::remove_file(external.path().join("proxy.cert")).unwrap();
        let _ = create_certificates(internal.path(), external.path(), SecUtf8::from("12345"));
    }

    #[test]
    fn test_config() {
        let internal = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();

        assert!(mtls_config(&internal.path(), &external.path(), SecUtf8::from("12345")).is_ok());
        for path in [
            internal.path().join("ca.cert"),
            internal.path().join("server.cert"),
            internal.path().join("server.key"),
            external.path().join("ca.cert"),
            external.path().join("proxy.cert"),
            external.path().join("proxy.key"),
        ] {
            assert!(std::fs::exists(path).unwrap());
        }
    }
}
