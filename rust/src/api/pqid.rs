//! Post-quantum identity signatures using ML-DSA-87 (FIPS 204).
//!
//! Port of monocles' `libsignal` `pqid` module. Stock signalapp/libsignal does
//! not expose this; the FRB wrapper owns it so Dart can match monocles
//! PQ-OMEMO2 hybrid identity (sign published bundles, verify on process).

use crate::api::error::LibSignalException;
use libcrux_ml_dsa::ml_dsa_87::{
    self, MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey,
};
use rand::{rngs::OsRng, TryRngCore as _};
use zeroize::Zeroize;

/// FIPS 204 domain-separation context for monocles PQ-OMEMO2 identity signatures.
const PQ_IDENTITY_CONTEXT: &[u8] = b"monocles:omemo2:pqid:v1";

/// Length in bytes of a serialized ML-DSA-87 public (verification) key.
pub const PQ_IDENTITY_PUBLIC_KEY_LEN: usize = 2592;
/// Length in bytes of a serialized ML-DSA-87 secret (signing) key.
pub const PQ_IDENTITY_SECRET_KEY_LEN: usize = 4896;
/// Length in bytes of an ML-DSA-87 signature.
pub const PQ_IDENTITY_SIGNATURE_LEN: usize = 4627;

fn wrong_len(what: &str, expected: usize, got: usize) -> LibSignalException {
    LibSignalException::invalid_argument(format!(
        "ML-DSA-87 {what} must be {expected} bytes, got {got}"
    ))
}

/// A post-quantum identity public key (ML-DSA-87 verification key).
pub struct PqIdentityKey {
    verifying_key: MLDSA87VerificationKey,
}

impl PqIdentityKey {
    pub(crate) fn from_native(verifying_key: MLDSA87VerificationKey) -> Self {
        Self { verifying_key }
    }

    pub(crate) fn native(&self) -> &MLDSA87VerificationKey {
        &self.verifying_key
    }

    /// Deserialize a raw ML-DSA-87 verification key (2592 bytes).
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<PqIdentityKey, LibSignalException> {
        let arr: [u8; PQ_IDENTITY_PUBLIC_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            wrong_len("public key", PQ_IDENTITY_PUBLIC_KEY_LEN, bytes.len())
        })?;
        Ok(Self {
            verifying_key: MLDSA87VerificationKey::new(arr),
        })
    }

    /// Serialize this verification key (2592 bytes).
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self.verifying_key.as_slice().to_vec())
    }

    /// Verify `signature` over `message` under the PQ-OMEMO2 context.
    #[flutter_rust_bridge::frb(sync)]
    pub fn verify(
        &self,
        message: Vec<u8>,
        signature: &PqSignature,
    ) -> Result<bool, LibSignalException> {
        Ok(ml_dsa_87::verify(
            &self.verifying_key,
            &message,
            PQ_IDENTITY_CONTEXT,
            signature.native(),
        )
        .is_ok())
    }
}

impl Clone for PqIdentityKey {
    fn clone(&self) -> Self {
        Self {
            verifying_key: MLDSA87VerificationKey::new(
                self.verifying_key
                    .as_slice()
                    .try_into()
                    .expect("fixed-length verification key"),
            ),
        }
    }
}

/// An ML-DSA-87 signature.
pub struct PqSignature {
    inner: MLDSA87Signature,
}

impl PqSignature {
    pub(crate) fn from_native(inner: MLDSA87Signature) -> Self {
        Self { inner }
    }

    pub(crate) fn native(&self) -> &MLDSA87Signature {
        &self.inner
    }

    /// Deserialize a raw ML-DSA-87 signature (4627 bytes).
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<PqSignature, LibSignalException> {
        let arr: [u8; PQ_IDENTITY_SIGNATURE_LEN] = bytes.as_slice().try_into().map_err(|_| {
            wrong_len("signature", PQ_IDENTITY_SIGNATURE_LEN, bytes.len())
        })?;
        Ok(Self {
            inner: MLDSA87Signature::new(arr),
        })
    }

    /// Serialize this signature (4627 bytes).
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self.inner.as_slice().to_vec())
    }
}

impl Clone for PqSignature {
    fn clone(&self) -> Self {
        Self {
            inner: MLDSA87Signature::new(
                self.inner
                    .as_slice()
                    .try_into()
                    .expect("fixed-length signature"),
            ),
        }
    }
}

/// A post-quantum identity key pair (ML-DSA-87).
pub struct PqIdentityKeyPair {
    signing_key: MLDSA87SigningKey,
    verifying_key: MLDSA87VerificationKey,
}

impl PqIdentityKeyPair {
    /// Generate a fresh ML-DSA-87 identity key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<PqIdentityKeyPair, LibSignalException> {
        let mut randomness = [0u8; 32];
        OsRng.try_fill_bytes(&mut randomness).map_err(|_| {
            LibSignalException::internal("failed to draw ML-DSA-87 keygen randomness")
        })?;
        let kp = ml_dsa_87::generate_key_pair(randomness);
        randomness.zeroize();
        Ok(Self {
            signing_key: kp.signing_key,
            verifying_key: kp.verification_key,
        })
    }

    /// Public verification key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn public_key(&self) -> Result<PqIdentityKey, LibSignalException> {
        Ok(PqIdentityKey::from_native(MLDSA87VerificationKey::new(
            self.verifying_key
                .as_slice()
                .try_into()
                .expect("fixed-length verification key"),
        )))
    }

    /// Sign `message` under the PQ-OMEMO2 domain-separation context.
    #[flutter_rust_bridge::frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> Result<PqSignature, LibSignalException> {
        let mut randomness = [0u8; 32];
        OsRng.try_fill_bytes(&mut randomness).map_err(|_| {
            LibSignalException::internal("failed to draw ML-DSA-87 signing randomness")
        })?;
        let signature = ml_dsa_87::sign(&self.signing_key, &message, PQ_IDENTITY_CONTEXT, randomness)
            .map_err(|e| {
                LibSignalException::invalid_argument(format!("ML-DSA-87 signing failed: {e:?}"))
            })?;
        randomness.zeroize();
        Ok(PqSignature::from_native(signature))
    }

    /// Serialize as signing-key bytes followed by verification-key bytes.
    ///
    /// # Security
    /// The returned bytes contain the long-term signing key. The caller must
    /// zero them when done.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        let mut out = Vec::with_capacity(PQ_IDENTITY_SECRET_KEY_LEN + PQ_IDENTITY_PUBLIC_KEY_LEN);
        out.extend_from_slice(self.signing_key.as_slice());
        out.extend_from_slice(self.verifying_key.as_slice());
        Ok(out)
    }

    /// Deserialize a key pair previously produced by [`Self::serialize`].
    ///
    /// # Security
    /// Input bytes are zeroized after parsing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<PqIdentityKeyPair, LibSignalException> {
        let expected = PQ_IDENTITY_SECRET_KEY_LEN + PQ_IDENTITY_PUBLIC_KEY_LEN;
        let result = (|| {
            if bytes.len() != expected {
                return Err(wrong_len("key pair", expected, bytes.len()));
            }
            let (sk, vk) = bytes.split_at(PQ_IDENTITY_SECRET_KEY_LEN);
            let sk_arr: [u8; PQ_IDENTITY_SECRET_KEY_LEN] =
                sk.try_into().expect("checked length");
            let vk_arr: [u8; PQ_IDENTITY_PUBLIC_KEY_LEN] =
                vk.try_into().expect("checked length");
            Ok(Self {
                signing_key: MLDSA87SigningKey::new(sk_arr),
                verifying_key: MLDSA87VerificationKey::new(vk_arr),
            })
        })();
        bytes.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let pair = PqIdentityKeyPair::generate().expect("generate");
        let public = pair.public_key().expect("public");
        let message = b"the bundle transcript digest".to_vec();
        let signature = pair.sign(message.clone()).expect("sign");
        assert!(public.verify(message, &signature).expect("verify"));
        assert!(!public
            .verify(b"tampered".to_vec(), &signature)
            .expect("verify"));
    }

    #[test]
    fn serialization_roundtrip() {
        let pair = PqIdentityKeyPair::generate().expect("generate");
        let message = b"transcript".to_vec();
        let signature = pair.sign(message.clone()).expect("sign");

        let pair2 = PqIdentityKeyPair::deserialize(pair.serialize().expect("ser")).expect("kp");
        let pub2 =
            PqIdentityKey::deserialize(pair.public_key().unwrap().serialize().unwrap()).unwrap();
        let sig2 = PqSignature::deserialize(signature.serialize().unwrap()).unwrap();

        assert!(pub2.verify(message.clone(), &sig2).unwrap());
        let sig_from_pair2 = pair2.sign(message).unwrap();
        assert!(pair
            .public_key()
            .unwrap()
            .verify(b"transcript".to_vec(), &sig_from_pair2)
            .unwrap());
    }

    #[test]
    fn deserialize_rejects_wrong_length() {
        assert!(PqIdentityKey::deserialize(vec![0u8; 10]).is_err());
        assert!(PqSignature::deserialize(vec![0u8; 10]).is_err());
        assert!(PqIdentityKeyPair::deserialize(vec![0u8; 10]).is_err());
    }
}
