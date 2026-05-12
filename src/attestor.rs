//! Single-attestor primitives: keypair, sign, verify.

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// A secret key (a non-zero scalar in BLS12-381's prime field).
#[derive(Debug, Clone)]
pub struct SecretKey(Scalar);

/// A public key (an element of G1 — 48 bytes compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(G1Affine);

/// A BLS signature (an element of G2 — 96 bytes compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(G2Affine);

/// A keypair bundled with helper sign/verify methods.
#[derive(Debug, Clone)]
pub struct Attestor {
    sk: SecretKey,
    pk: PublicKey,
}

impl Attestor {
    /// Generate a fresh BLS attestor from a CSPRNG.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let sk_scalar = Scalar::from_bytes_wide(&bytes);
        let pk_g1 = (G1Projective::generator() * sk_scalar).to_affine();
        Attestor {
            sk: SecretKey(sk_scalar),
            pk: PublicKey(pk_g1),
        }
    }

    /// Borrow the attestor's public key.
    pub fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Sign a message under this attestor's secret key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        sign(&self.sk, message)
    }
}

/// Sign a message under a secret key, returning a G2 signature.
pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature {
    let h = hash_to_scalar(message);
    let h_g2 = G2Projective::generator() * h;
    let sig = h_g2 * sk.0;
    Signature(sig.to_affine())
}

/// Verify a signature against a single public key and message.
pub fn verify(pk: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let h = hash_to_scalar(message);
    let h_g2 = (G2Projective::generator() * h).to_affine();
    let g1 = G1Affine::generator();
    pairing(&g1, &sig.0) == pairing(&pk.0, &h_g2)
}

/// Aggregate a slice of signatures by point addition in G2.
pub fn aggregate_signatures(sigs: &[Signature]) -> Signature {
    let mut acc = G2Projective::identity();
    for s in sigs {
        acc += G2Projective::from(s.0);
    }
    Signature(acc.to_affine())
}

/// Aggregate a slice of public keys by point addition in G1.
pub fn aggregate_public_keys(pks: &[PublicKey]) -> PublicKey {
    let mut acc = G1Projective::identity();
    for pk in pks {
        acc += G1Projective::from(pk.0);
    }
    PublicKey(acc.to_affine())
}

/// Hash a message to a scalar via SHA-256 (textbook BLS; see crate-level
/// security note about why this is not production-safe).
fn hash_to_scalar(message: &[u8]) -> Scalar {
    let digest = Sha256::digest(message);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    Scalar::from_bytes_wide(&wide)
}

impl PublicKey {
    /// Serialize the public key to 48 compressed bytes.
    pub fn to_bytes(self) -> [u8; 48] {
        self.0.to_compressed()
    }
}

impl Signature {
    /// Serialize the signature to 96 compressed bytes.
    pub fn to_bytes(self) -> [u8; 96] {
        self.0.to_compressed()
    }
}
