//! Integration-ish tests for PQ identity attachment + transcript verify
//! (the check that runs inside `process_prekey_bundle_inner` before PQXDH).

#![cfg(test)]

use crate::api::bundle::PreKeyBundle;
use crate::api::pq_bundle::{pq_bundle_transcript, pq_kem_binding, KemOneTimeKey};
use crate::api::pqid::PqIdentityKeyPair;
use libsignal_protocol::{IdentityKeyPair, KeyPair, kem};
use rand::{rngs::OsRng, TryRngCore as _};

fn classical_bundle() -> (PreKeyBundle, IdentityKeyPair, KeyPair) {
    let mut rng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    let signed = KeyPair::generate(&mut rng);
    let signed_sig = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), &mut rng)
        .expect("spk sig");
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    // ML-KEM-1024 when the feature is on; Kyber1024 is fine for bundle shape here.
    let kyber_sig = identity
        .private_key()
        .calculate_signature(&kyber.public_key.serialize(), &mut rng)
        .expect("kem sig");

    let bundle = PreKeyBundle::new(
        1,
        1,
        None,
        None,
        1,
        signed.public_key.serialize().into_vec(),
        signed_sig.into_vec(),
        identity.public_key().serialize().into_vec(),
        1,
        kyber.public_key.serialize().into_vec(),
        kyber_sig.into_vec(),
    )
    .expect("bundle");
    (bundle, identity, signed)
}

#[test]
fn with_pq_identity_verifies_good_signature() {
    let (plain, identity, signed) = classical_bundle();
    let pq = PqIdentityKeyPair::generate().expect("pq gen");
    let pq_pub = pq.public_key().unwrap().serialize().unwrap();

    let binding = pq_kem_binding(
        1,
        plain.kyber_pre_key_public().unwrap(),
        vec![KemOneTimeKey {
            id: 10,
            public_key: plain.kyber_pre_key_public().unwrap(),
        }],
    )
    .unwrap();

    let transcript = pq_bundle_transcript(
        identity.public_key().serialize().into_vec(),
        pq_pub.clone(),
        1,
        signed.public_key.serialize().into_vec(),
        binding.clone(),
    )
    .unwrap();
    let sig = pq.sign(transcript).unwrap().serialize().unwrap();

    let with_pq = plain
        .with_pq_identity(pq_pub, sig, binding)
        .expect("with_pq");
    assert!(with_pq.pq_identity_key().unwrap().is_some());
    assert!(with_pq.pq_signature().unwrap().is_some());
    assert_eq!(with_pq.pq_kem_binding_digest().unwrap().unwrap().len(), 64);
}

#[test]
fn with_pq_identity_rejects_wrong_binding_length() {
    let (plain, _, _) = classical_bundle();
    let pq = PqIdentityKeyPair::generate().unwrap();
    let err = plain.with_pq_identity(
        pq.public_key().unwrap().serialize().unwrap(),
        vec![0u8; 4627],
        vec![0u8; 32], // old SHA-256 width — must refuse
    );
    assert!(err.is_err());
}
