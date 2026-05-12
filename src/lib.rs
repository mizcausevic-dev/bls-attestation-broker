//! Multi-signer attestation broker using BLS12-381 aggregate signatures.
//!
//! Three attestors signing the same message produce three signatures
//! that aggregate (by curve addition) into a single 96-byte signature.
//! A verifier checks the aggregate against the *sum* of the attestors'
//! public keys in two pairings — regardless of how many attestors
//! participated.
//!
//! ```
//! use bls_attestation_broker::{Attestor, AttestationBroker};
//! use rand::rngs::OsRng;
//!
//! let message = b"agent foo authorized by tenants a, b, c";
//!
//! let a = Attestor::generate(&mut OsRng);
//! let b = Attestor::generate(&mut OsRng);
//! let c = Attestor::generate(&mut OsRng);
//!
//! let mut broker = AttestationBroker::new(message);
//! broker.add(&a);
//! broker.add(&b);
//! broker.add(&c);
//!
//! let attestation = broker.finalize();
//! assert!(attestation.verify(&[a.public_key(), b.public_key(), c.public_key()], message));
//! ```
//!
//! ## Security note
//!
//! This crate implements the textbook BLS signature scheme using
//! hash-to-scalar followed by scalar multiplication of the G2
//! generator. That construction is simpler to teach and audit than
//! a full RFC 9380 hash-to-curve implementation, but it is **not
//! suitable for production deployments**. Use it for prototyping,
//! reference implementations, and educational material; for
//! production, route to a vetted BLS library such as `blst` or
//! `bls-signatures`.

#![warn(missing_docs)]
#![warn(clippy::all)]

mod attestor;
mod broker;

pub use attestor::{Attestor, PublicKey, SecretKey, Signature};
pub use broker::{Attestation, AttestationBroker};
