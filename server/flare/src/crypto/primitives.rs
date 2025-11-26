use secstr::SecStr;

use crate::{api::error::RestError, crypto::HASH_ALGORITHM};

pub struct Cipher {
    key: SecStr,
}

impl Cipher {
    const ALGO_NAME: &'static str = "AES-256/GCM";

    pub fn new(key: &SecStr) -> Self {
        let cipher = botan::Cipher::new(Self::ALGO_NAME, botan::CipherDirection::Encrypt).unwrap();
        assert_eq!(
            key.unsecure().len(),
            cipher.key_spec().unwrap().maximum_keylength()
        );
        Self { key: key.clone() }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<String, RestError> {
        let mut cipher = botan::Cipher::new(Self::ALGO_NAME, botan::CipherDirection::Encrypt)?;
        cipher.set_key(self.key.unsecure())?;

        let nonce =
            botan::RandomNumberGenerator::new_system()?.read(cipher.default_nonce_length())?;

        let encrypted = cipher.process(&nonce, data)?;
        let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&encrypted);

        Ok(botan::hex_encode(&result)?)
    }

    pub fn decrypt(&self, data: &str) -> Result<Vec<u8>, RestError> {
        let mut cipher = botan::Cipher::new(Self::ALGO_NAME, botan::CipherDirection::Decrypt)?;
        cipher.set_key(self.key.unsecure())?;

        let data = botan::hex_decode(data)?;
        let nonce_size = cipher.default_nonce_length();
        let nonce = &data[..nonce_size];
        let decrypted = cipher.process(nonce, &data[nonce_size..])?;
        Ok(decrypted.to_vec())
    }
}

pub struct Hasher;

impl Hasher {
    pub fn hash(data: &[u8]) -> Result<String, RestError> {
        let mut hasher = botan::HashFunction::new(HASH_ALGORITHM)?;
        hasher.update(data)?;
        let hash = hasher.finish()?;
        Ok(botan::hex_encode(&hash)?)
    }
}

#[cfg(test)]
mod tests {
    use secstr::SecStr;

    use super::Cipher;

    #[test]
    fn test_cipher() {
        let mut key = SecStr::new(vec![0; 32]);
        botan::RandomNumberGenerator::new_userspace()
            .unwrap()
            .fill(&mut key.unsecure_mut())
            .unwrap();
        let other_key = SecStr::new(vec![1; 32]);

        let cipher = Cipher::new(&key);
        let message = b"Hello, world!";
        let encrypted = cipher.encrypt(message).unwrap();
        assert_ne!(message, encrypted.as_bytes());
        assert_eq!(*message, *cipher.decrypt(&encrypted).unwrap());

        let other_cipher = Cipher::new(&other_key);
        assert!(other_cipher.decrypt(&encrypted).is_err());
    }

    #[test]
    #[should_panic]
    fn test_cipher_key_len() {
        let key = SecStr::new(vec![0; 31]);
        let _ = Cipher::new(&key);
    }
}
