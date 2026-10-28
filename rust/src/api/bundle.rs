//! PreKey bundle API using libsignal-protocol.

use crate::api::error::{LibSignalErrorCode, LibSignalException};
use crate::api::pq_bundle::PQ_KEM_BINDING_LEN;
use crate::api::pqid::{PqIdentityKey, PqSignature};
use libsignal_protocol::{
    DeviceId, IdentityKey, KyberPreKeyId, PreKeyBundle as NativePreKeyBundle, PreKeyId,
    PublicKey as NativePublicKey, SignedPreKeyId, kem,
};

/// A pre-key bundle containing all the keys needed to establish a session.
///
/// Optionally carries a monocles PQ-OMEMO2 hybrid identity (`with_pq_identity`).
/// When present, [`crate::api::session_builder::process_prekey_bundle_with_callbacks`]
/// verifies the ML-DSA-87 signature over the v3 transcript before establishing
/// the session — matching monocles' patched `process_prekey_bundle`.
pub struct PreKeyBundle {
    inner: NativePreKeyBundle,
    pq_identity: Option<(PqIdentityKey, PqSignature)>,
    pq_kem_binding: Option<Vec<u8>>,
}

impl PreKeyBundle {
    /// Create from native libsignal PreKeyBundle.
    pub(crate) fn from_native(bundle: NativePreKeyBundle) -> Self {
        Self {
            inner: bundle,
            pq_identity: None,
            pq_kem_binding: None,
        }
    }

    /// Get the inner native bundle (for use by other modules).
    pub(crate) fn native(&self) -> &NativePreKeyBundle {
        &self.inner
    }

    /// Post-quantum identity + signature, if attached via [`Self::with_pq_identity`].
    pub(crate) fn pq_identity(&self) -> Option<(&PqIdentityKey, &PqSignature)> {
        self.pq_identity.as_ref().map(|(k, s)| (k, s))
    }

    /// ML-KEM binding digest attached with the PQ identity, if any.
    pub(crate) fn pq_kem_binding(&self) -> Option<&[u8]> {
        self.pq_kem_binding.as_deref()
    }

    /// Create a new pre-key bundle from serialized keys.
    ///
    /// # Arguments
    /// * `registration_id` - The registration ID
    /// * `device_id` - The device ID
    /// * `pre_key_id` - The pre-key ID (None for no pre-key)
    /// * `pre_key_public` - The pre-key public key bytes (None for no pre-key)
    /// * `signed_pre_key_id` - The signed pre-key ID
    /// * `signed_pre_key_public` - The signed pre-key public key bytes
    /// * `signed_pre_key_signature` - The signature of the signed pre-key
    /// * `identity_key` - The identity public key bytes
    /// * `kyber_pre_key_id` - The Kyber pre-key ID (required by libsignal)
    /// * `kyber_pre_key_public` - The Kyber pre-key public key bytes (required by libsignal)
    /// * `kyber_pre_key_signature` - The Kyber pre-key signature (required by libsignal)
    // A PreKeyBundle genuinely carries this many components (X3DH signed
    // pre-key + optional one-time pre-key + Kyber pre-key + identity); the
    // argument list mirrors libsignal's own `PreKeyBundle::new`, so the count
    // is inherent to the bundle, not a refactor smell.
    #[allow(clippy::too_many_arguments)]
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: Option<u32>,
        pre_key_public: Option<Vec<u8>>,
        signed_pre_key_id: u32,
        signed_pre_key_public: Vec<u8>,
        signed_pre_key_signature: Vec<u8>,
        identity_key: Vec<u8>,
        kyber_pre_key_id: u32,
        kyber_pre_key_public: Vec<u8>,
        kyber_pre_key_signature: Vec<u8>,
    ) -> Result<PreKeyBundle, LibSignalException> {
        // Parse the device ID
        let dev_id = DeviceId::try_from(device_id)
            .map_err(|_| {
                LibSignalException::invalid_argument(format!(
                    "Invalid device ID: {} (must be 1-127)",
                    device_id
                ))
            })?;

        // Parse the optional pre-key
        let pre_key = match (pre_key_id, pre_key_public) {
            (Some(id), Some(bytes)) => {
                let public_key =
                    NativePublicKey::deserialize(&bytes).map_err(LibSignalException::from)?;
                if !public_key.is_canonical() {
                    return Err(LibSignalException::new(
                        LibSignalErrorCode::InvalidKey,
                        "Pre-key public key is a low-order point",
                    ));
                }
                Some((PreKeyId::from(id), public_key))
            }
            _ => None,
        };

        // Parse the signed pre-key
        let signed_pre_key_pub =
            NativePublicKey::deserialize(&signed_pre_key_public).map_err(LibSignalException::from)?;
        if !signed_pre_key_pub.is_canonical() {
            return Err(LibSignalException::new(
                LibSignalErrorCode::InvalidKey,
                "Signed pre-key public key is a low-order point",
            ));
        }

        // Parse the identity key
        let identity_pub =
            NativePublicKey::deserialize(&identity_key).map_err(LibSignalException::from)?;
        if !identity_pub.is_canonical() {
            return Err(LibSignalException::new(
                LibSignalErrorCode::InvalidKey,
                "Identity public key is a low-order point",
            ));
        }
        let identity = IdentityKey::new(identity_pub);

        // Parse the Kyber pre-key
        let kyber_pub =
            kem::PublicKey::deserialize(&kyber_pre_key_public).map_err(LibSignalException::from)?;

        // Create the bundle
        let native = NativePreKeyBundle::new(
            registration_id,
            dev_id,
            pre_key,
            SignedPreKeyId::from(signed_pre_key_id),
            signed_pre_key_pub,
            signed_pre_key_signature,
            KyberPreKeyId::from(kyber_pre_key_id),
            kyber_pub,
            kyber_pre_key_signature,
            identity,
        )
        .map_err(LibSignalException::from)?;

        Ok(PreKeyBundle {
            inner: native,
            pq_identity: None,
            pq_kem_binding: None,
        })
    }

    /// Attach a monocles PQ-OMEMO2 hybrid identity (ML-DSA-87 public key and its
    /// signature over [`crate::api::pq_bundle::pq_bundle_transcript`]) together
    /// with the 64-byte ML-KEM binding digest
    /// ([`crate::api::pq_bundle::pq_kem_binding`]) recomputed from the fetched
    /// bundle. When present, processing this bundle verifies the signature and
    /// aborts on failure.
    #[flutter_rust_bridge::frb(sync)]
    pub fn with_pq_identity(
        &self,
        pq_identity_key: Vec<u8>,
        pq_signature: Vec<u8>,
        kem_binding: Vec<u8>,
    ) -> Result<PreKeyBundle, LibSignalException> {
        if kem_binding.len() != PQ_KEM_BINDING_LEN {
            return Err(LibSignalException::invalid_argument(format!(
                "ML-KEM binding digest must be {PQ_KEM_BINDING_LEN} bytes, got {}",
                kem_binding.len()
            )));
        }
        let pq_key = PqIdentityKey::deserialize(pq_identity_key)?;
        let pq_sig = PqSignature::deserialize(pq_signature)?;
        Ok(PreKeyBundle {
            inner: self.inner.clone(),
            pq_identity: Some((pq_key, pq_sig)),
            pq_kem_binding: Some(kem_binding),
        })
    }

    /// Serialized ML-DSA-87 identity public key, if a PQ identity is attached.
    #[flutter_rust_bridge::frb(sync)]
    pub fn pq_identity_key(&self) -> Result<Option<Vec<u8>>, LibSignalException> {
        match &self.pq_identity {
            Some((key, _)) => Ok(Some(key.serialize()?)),
            None => Ok(None),
        }
    }

    /// Serialized ML-DSA-87 bundle signature, if a PQ identity is attached.
    #[flutter_rust_bridge::frb(sync)]
    pub fn pq_signature(&self) -> Result<Option<Vec<u8>>, LibSignalException> {
        match &self.pq_identity {
            Some((_, sig)) => Ok(Some(sig.serialize()?)),
            None => Ok(None),
        }
    }

    /// The 64-byte ML-KEM binding digest, if a PQ identity is attached.
    #[flutter_rust_bridge::frb(sync)]
    pub fn pq_kem_binding_digest(&self) -> Result<Option<Vec<u8>>, LibSignalException> {
        Ok(self.pq_kem_binding.clone())
    }

    /// Get the registration ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn registration_id(&self) -> Result<u32, LibSignalException> {
        self.inner.registration_id().map_err(LibSignalException::from)
    }

    /// Get the device ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn device_id(&self) -> Result<u32, LibSignalException> {
        Ok(self.inner.device_id().map_err(LibSignalException::from)?.into())
    }

    /// Get the pre-key ID (returns None if no pre-key).
    #[flutter_rust_bridge::frb(sync)]
    pub fn pre_key_id(&self) -> Result<Option<u32>, LibSignalException> {
        Ok(self
            .inner
            .pre_key_id()
            .map_err(LibSignalException::from)?
            .map(|id| id.into()))
    }

    /// Get the pre-key public key (returns None if no pre-key).
    #[flutter_rust_bridge::frb(sync)]
    pub fn pre_key_public(&self) -> Result<Option<Vec<u8>>, LibSignalException> {
        match self.inner.pre_key_public().map_err(LibSignalException::from)? {
            Some(key) => Ok(Some(key.serialize().into_vec())),
            None => Ok(None),
        }
    }

    /// Get the signed pre-key ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signed_pre_key_id(&self) -> Result<u32, LibSignalException> {
        Ok(self
            .inner
            .signed_pre_key_id()
            .map_err(LibSignalException::from)?
            .into())
    }

    /// Get the signed pre-key public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signed_pre_key_public(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self
            .inner
            .signed_pre_key_public()
            .map_err(LibSignalException::from)?
            .serialize()
            .into_vec())
    }

    /// Get the signed pre-key signature.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signed_pre_key_signature(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self
            .inner
            .signed_pre_key_signature()
            .map_err(LibSignalException::from)?
            .to_vec())
    }

    /// Get the identity public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn identity_key(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self
            .inner
            .identity_key()
            .map_err(LibSignalException::from)?
            .serialize()
            .into_vec())
    }

    /// Get the Kyber pre-key ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn kyber_pre_key_id(&self) -> Result<u32, LibSignalException> {
        Ok(self
            .inner
            .kyber_pre_key_id()
            .map_err(LibSignalException::from)?
            .into())
    }

    /// Get the Kyber pre-key public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn kyber_pre_key_public(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self
            .inner
            .kyber_pre_key_public()
            .map_err(LibSignalException::from)?
            .serialize()
            .into_vec())
    }

    /// Get the Kyber pre-key signature.
    #[flutter_rust_bridge::frb(sync)]
    pub fn kyber_pre_key_signature(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self
            .inner
            .kyber_pre_key_signature()
            .map_err(LibSignalException::from)?
            .to_vec())
    }
}
