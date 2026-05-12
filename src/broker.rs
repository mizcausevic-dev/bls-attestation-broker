//! Broker that accumulates per-attestor signatures over a single
//! message and produces an aggregate attestation.

use crate::attestor::{aggregate_public_keys, aggregate_signatures, verify};
use crate::{Attestor, PublicKey, Signature};

/// Accumulates signatures from multiple attestors over a common message.
#[derive(Debug, Clone)]
pub struct AttestationBroker {
    message: Vec<u8>,
    signatures: Vec<Signature>,
    public_keys: Vec<PublicKey>,
}

impl AttestationBroker {
    /// Start a new broker for the given message.
    pub fn new(message: &[u8]) -> Self {
        Self {
            message: message.to_vec(),
            signatures: Vec::new(),
            public_keys: Vec::new(),
        }
    }

    /// Add a single attestor's signature to the running aggregate.
    pub fn add(&mut self, attestor: &Attestor) {
        self.signatures.push(attestor.sign(&self.message));
        self.public_keys.push(attestor.public_key());
    }

    /// Add a pre-computed signature for an attestor (useful when the
    /// attestor signs in a different process and only hands over the
    /// signature + public key).
    pub fn add_external(&mut self, pk: PublicKey, sig: Signature) {
        self.signatures.push(sig);
        self.public_keys.push(pk);
    }

    /// Number of attestors that have contributed so far.
    pub fn signer_count(&self) -> usize {
        self.signatures.len()
    }

    /// Compute the aggregate attestation. Requires at least one signer.
    pub fn finalize(&self) -> Attestation {
        assert!(!self.signatures.is_empty(), "no attestors registered");
        Attestation {
            message: self.message.clone(),
            aggregate_signature: aggregate_signatures(&self.signatures),
            signer_count: self.signatures.len(),
        }
    }
}

/// An aggregate attestation: one message, one aggregate signature,
/// plus the count of attestors that contributed.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The exact bytes the attestors signed.
    pub message: Vec<u8>,
    /// Sum (in G2) of every attestor's signature.
    pub aggregate_signature: Signature,
    /// How many attestors contributed.
    pub signer_count: usize,
}

impl Attestation {
    /// Verify the aggregate signature against a slice of attestor
    /// public keys. Returns true if and only if `signers` is exactly
    /// the set of public keys whose signatures were aggregated and
    /// the aggregate is a valid BLS aggregate signature on the
    /// attestation's message.
    pub fn verify(&self, signers: &[PublicKey], message: &[u8]) -> bool {
        if message != self.message.as_slice() {
            return false;
        }
        if signers.len() != self.signer_count {
            return false;
        }
        let agg_pk = aggregate_public_keys(signers);
        verify(&agg_pk, message, &self.aggregate_signature)
    }
}
