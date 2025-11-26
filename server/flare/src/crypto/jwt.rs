use botan::{Privkey, Pubkey};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier},
    custom_provider::{AlgorithmFamily, Error as SigError, Signer, Verifier},
    errors::{Error, ErrorKind},
};

struct EdDSASigner(Privkey);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self, Error> {
        if encoding_key.family != AlgorithmFamily::Ed {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }

        Ok(Self(
            Privkey::load_der(encoding_key.inner()).map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, SigError> {
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(SigError::from_source)?;
        let mut signer = botan::Signer::new(&self.0, "Pure").map_err(SigError::from_source)?;
        signer.update(msg).map_err(SigError::from_source)?;
        signer.finish(&mut rng).map_err(SigError::from_source)
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

struct EdDSAVerifier(Pubkey);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self, Error> {
        if decoding_key.family != AlgorithmFamily::Ed {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }

        Ok(Self(
            Pubkey::load_ed25519(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), SigError> {
        let mut verifier = botan::Verifier::new(&self.0, "Pure").map_err(SigError::from_source)?;
        verifier.update(msg).map_err(SigError::from_source)?;
        verifier
            .finish(signature)
            .map_err(SigError::from_source)?
            .then_some(())
            .ok_or(SigError::new())
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    let jwt_signer = match algorithm {
        Algorithm::EdDSA => Box::new(EdDSASigner::new(key)?) as Box<dyn JwtSigner>,
        _ => unreachable!(),
    };

    Ok(jwt_signer)
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
    let jwt_verifier = match algorithm {
        Algorithm::EdDSA => Box::new(EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
        _ => unreachable!(),
    };

    Ok(jwt_verifier)
}

pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        signer_factory: new_signer,
        verifier_factory: new_verifier,
        jwk_utils: JwkUtils::default(),
    }
}
