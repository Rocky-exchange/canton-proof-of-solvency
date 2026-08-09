//! Ed25519 detached signatures over a report digest (SPEC §8).

/// Why a signature check failed. Distinguished so a verifier can tell an
/// unknown publisher from a forged one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    MalformedPublicKey,
    MalformedSignature,
    BadSignature,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedPublicKey => write!(f, "public key is not 32 bytes of hex"),
            Self::MalformedSignature => write!(f, "signature is not 64 bytes of hex"),
            Self::BadSignature => write!(f, "signature does not verify under this key"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// A publisher's signing key. Held only by the producer; never serialized.
pub struct ReportSigner {
    key: ed25519_dalek::SigningKey,
}

impl ReportSigner {
    /// Deterministic from a 32-byte seed, so golden vectors can pin exact
    /// signature bytes. Ed25519 signatures are deterministic by construction.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> String {
        use ed25519_dalek::Signer;
        hex::encode(self.key.sign(digest).to_bytes())
    }
}

fn decode<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

pub fn verify_signature(
    public_key_hex: &str,
    digest: &[u8; 32],
    signature_hex: &str,
) -> Result<(), SignatureError> {
    use ed25519_dalek::Verifier;
    let key_bytes = decode::<32>(public_key_hex).ok_or(SignatureError::MalformedPublicKey)?;
    let sig_bytes = decode::<64>(signature_hex).ok_or(SignatureError::MalformedSignature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| SignatureError::MalformedPublicKey)?;
    key.verify(digest, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .map_err(|_| SignatureError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];
    const DIGEST: [u8; 32] = [42u8; 32];

    #[test]
    fn a_signature_verifies_under_its_own_public_key() {
        let signer = ReportSigner::from_seed(&SEED);
        let sig = signer.sign_digest(&DIGEST);
        assert_eq!(
            verify_signature(&signer.public_key_hex(), &DIGEST, &sig),
            Ok(())
        );
    }

    #[test]
    fn signing_is_deterministic_so_vectors_can_pin_it() {
        let a = ReportSigner::from_seed(&SEED).sign_digest(&DIGEST);
        let b = ReportSigner::from_seed(&SEED).sign_digest(&DIGEST);
        assert_eq!(a, b);
        assert_eq!(a.len(), 128, "64 bytes as hex");
    }

    #[test]
    fn a_signature_fails_under_a_different_public_key() {
        let sig = ReportSigner::from_seed(&SEED).sign_digest(&DIGEST);
        let other = ReportSigner::from_seed(&[8u8; 32]);
        assert_eq!(
            verify_signature(&other.public_key_hex(), &DIGEST, &sig),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn a_signature_fails_over_a_different_digest() {
        let signer = ReportSigner::from_seed(&SEED);
        let sig = signer.sign_digest(&DIGEST);
        assert_eq!(
            verify_signature(&signer.public_key_hex(), &[43u8; 32], &sig),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn malformed_key_and_signature_are_distinguished_from_forgery() {
        let signer = ReportSigner::from_seed(&SEED);
        let sig = signer.sign_digest(&DIGEST);
        assert_eq!(
            verify_signature("not-hex", &DIGEST, &sig),
            Err(SignatureError::MalformedPublicKey)
        );
        assert_eq!(
            verify_signature(&signer.public_key_hex(), &DIGEST, "abcd"),
            Err(SignatureError::MalformedSignature)
        );
    }
}
