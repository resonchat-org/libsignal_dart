//! monocles PQ-OMEMO2 bundle transcript + ML-KEM binding digest.
//!
//! Byte-identical to monocles `pq_bundle_transcript` / `pq_kem_binding`
//! (proto-XEP §4.9.1). Used when attaching a PQ identity to a pre-key bundle
//! and when `process_prekey_bundle` verifies the ML-DSA-87 signature.

use crate::api::error::LibSignalException;
use sha3::{Digest, Sha3_512};

/// Domain-separation label for the v3 identity transcript.
const PQ_BUNDLE_TRANSCRIPT_LABEL: &[u8] = b"monocles:omemo2:pq-bundle:v3";
/// Domain-separation label for the ML-KEM binding digest.
const PQ_KEM_BINDING_LABEL: &[u8] = b"monocles:omemo2:kem-binding:v2";
const PQ_IDENTITY_ALGORITHM: &[u8] = b"ML-DSA-87";
const PQ_KEM_ALGORITHM: &[u8] = b"ML-KEM-1024";

/// Size of the ML-KEM binding digest (and its inner manifest hash).
pub const PQ_KEM_BINDING_LEN: usize = 64;

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// One published ML-KEM one-time pre-key as it appears in the bundle document.
pub struct KemOneTimeKey {
    pub id: u32,
    /// Serialized public key bytes (libsignal tagged form, leading `0x0A`).
    pub public_key: Vec<u8>,
}

/// Compute the 64-byte ML-KEM binding digest over a bundle's post-quantum
/// pre-keys (monocles `PqBundle.kemBinding`).
///
/// Known-answer (proto-XEP §4.9.1 / monocles Java+Rust):
/// kemSpkId=1, KEM-SPK=`0xAA`×4, OPKs (2,`0xBB`×3) and (3,`0xCC`×5) →
/// `7f93e762…3c8c98f2`.
#[flutter_rust_bridge::frb(sync)]
pub fn pq_kem_binding(
    kem_signed_pre_key_id: u32,
    kem_signed_pre_key_public: Vec<u8>,
    one_time: Vec<KemOneTimeKey>,
) -> Result<Vec<u8>, LibSignalException> {
    let manifest: [u8; PQ_KEM_BINDING_LEN] = if one_time.is_empty() {
        [0u8; PQ_KEM_BINDING_LEN]
    } else {
        let mut m = Sha3_512::new();
        for k in &one_time {
            m.update(k.id.to_be_bytes());
            m.update((k.public_key.len() as u32).to_be_bytes());
            m.update(&k.public_key);
        }
        m.finalize().into()
    };
    let mut h = Sha3_512::new();
    h.update(PQ_KEM_BINDING_LABEL);
    h.update((PQ_KEM_ALGORITHM.len() as u32).to_be_bytes());
    h.update(PQ_KEM_ALGORITHM);
    h.update(kem_signed_pre_key_id.to_be_bytes());
    h.update((kem_signed_pre_key_public.len() as u32).to_be_bytes());
    h.update(&kem_signed_pre_key_public);
    h.update((manifest.len() as u32).to_be_bytes());
    h.update(manifest);
    Ok(h.finalize().to_vec())
}

/// Build the canonical transcript bound by a bundle's post-quantum identity
/// signature (monocles `PqBundle.transcript`).
///
/// `identity_key` and `signed_pre_key_public` are libsignal serialize form
/// (33 bytes, leading `0x05`). `pq_identity_key` is the raw ML-DSA-87
/// verification key (2592 bytes). `kem_binding` is the 64-byte digest from
/// [`pq_kem_binding`].
#[flutter_rust_bridge::frb(sync)]
pub fn pq_bundle_transcript(
    identity_key: Vec<u8>,
    pq_identity_key: Vec<u8>,
    signed_pre_key_id: u32,
    signed_pre_key_public: Vec<u8>,
    kem_binding: Vec<u8>,
) -> Result<Vec<u8>, LibSignalException> {
    let mut out = Vec::with_capacity(
        PQ_BUNDLE_TRANSCRIPT_LABEL.len()
            + PQ_IDENTITY_ALGORITHM.len()
            + identity_key.len()
            + pq_identity_key.len()
            + signed_pre_key_public.len()
            + kem_binding.len()
            + 44,
    );
    out.extend_from_slice(PQ_BUNDLE_TRANSCRIPT_LABEL);
    push_len_prefixed(&mut out, PQ_IDENTITY_ALGORITHM);
    push_len_prefixed(&mut out, &identity_key);
    push_len_prefixed(&mut out, &pq_identity_key);
    out.extend_from_slice(&signed_pre_key_id.to_be_bytes());
    push_len_prefixed(&mut out, &signed_pre_key_public);
    push_len_prefixed(&mut out, &kem_binding);
    Ok(out)
}

/// Internal transcript builder used by `process_prekey_bundle` (avoids
/// re-serializing keys the native bundle already holds).
pub(crate) fn pq_bundle_transcript_slices(
    identity_key: &[u8],
    pq_identity_key: &[u8],
    signed_pre_key_id: u32,
    signed_pre_key_public: &[u8],
    kem_binding: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PQ_BUNDLE_TRANSCRIPT_LABEL.len()
            + PQ_IDENTITY_ALGORITHM.len()
            + identity_key.len()
            + pq_identity_key.len()
            + signed_pre_key_public.len()
            + kem_binding.len()
            + 44,
    );
    out.extend_from_slice(PQ_BUNDLE_TRANSCRIPT_LABEL);
    push_len_prefixed(&mut out, PQ_IDENTITY_ALGORITHM);
    push_len_prefixed(&mut out, identity_key);
    push_len_prefixed(&mut out, pq_identity_key);
    out.extend_from_slice(&signed_pre_key_id.to_be_bytes());
    push_len_prefixed(&mut out, signed_pre_key_public);
    push_len_prefixed(&mut out, kem_binding);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(len: usize, value: u8) -> Vec<u8> {
        vec![value; len]
    }

    #[test]
    fn kem_binding_known_answer() {
        let one_time = vec![
            KemOneTimeKey {
                id: 2,
                public_key: filled(3, 0xBB),
            },
            KemOneTimeKey {
                id: 3,
                public_key: filled(5, 0xCC),
            },
        ];
        let binding = pq_kem_binding(1, filled(4, 0xAA), one_time).unwrap();
        assert_eq!(binding.len(), 64);
        const EXPECTED: &str = concat!(
            "7f93e76279a9e5c4dffe34e20c809fb2d1ef8dafaebf26742725aa4a1eba4d0f",
            "fac892689509fa655a04fb8a6d6c0beff91f757ab714b6cb8c8cd3303c8c98f2",
        );
        let expected: Vec<u8> = (0..EXPECTED.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&EXPECTED[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(binding, expected);
    }
}
