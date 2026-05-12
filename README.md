# bls-attestation-broker

Multi-signer attestation broker using **BLS12-381 aggregate signatures**. N attestor signatures collapse into one 96-byte aggregate signature verifiable in two pairings — regardless of how many attestors contributed.

Useful when you have a chain of approvals (tenant + admin + policy bot) and want to attach a single compact proof to the resulting action, rather than concatenating N individual signatures.

## Install

```toml
[dependencies]
bls-attestation-broker = "0.1"
```

## Quickstart

```rust
use bls_attestation_broker::{AttestationBroker, Attestor};
use rand::rngs::OsRng;

let mut rng = OsRng;
let tenant_a = Attestor::generate(&mut rng);
let tenant_b = Attestor::generate(&mut rng);
let tenant_c = Attestor::generate(&mut rng);

let message = b"agent='customer-support-tier-1' tool='ticket-create' approved=2026-05-12";

let mut broker = AttestationBroker::new(message);
broker.add(&tenant_a);
broker.add(&tenant_b);
broker.add(&tenant_c);

let attestation = broker.finalize();
// attestation.aggregate_signature is 96 bytes for any N attestors

let signers = [tenant_a.public_key(), tenant_b.public_key(), tenant_c.public_key()];
assert!(attestation.verify(&signers, message));
```

## Demo

```bash
cargo run --release --example demo
```

```
message (82 bytes): agent='customer-support-tier-1' tool='ticket-create' approved=2026-05-12T05:00:00Z

aggregated 3 attestor signatures into one signature
aggregate signature: 96 bytes (af599c9405d4c6de9bf55431c868eea2…)

verification: ACCEPT
verification with imposter for tenant_b: REJECT (expected)
verification of tampered message: REJECT (expected)
```

## Why BLS aggregate?

| | Ed25519 (per-signer) | BLS aggregate |
|---|---|---|
| Bytes on the wire for N signers | `64 × N` | **96** |
| Verifier work | `N` pairing-free verifies | **2 pairings** |
| Public key compactness | `32 × N` | `48 × N` (or one 48-byte aggregate pk for same-message) |

The win is the *signature*, not the public keys — for many use cases (audit logs, multi-tenant approvals, certificate co-signing) you save a lot of bytes and a lot of CPU on the verify path.

## Tests

Eight integration tests in [`tests/bls.rs`](tests/bls.rs):

- single signer → verify
- three signers → aggregate → verify
- one imposter in the signer set → reject
- tampered message → reject
- mismatched signer count → reject
- aggregate is exactly 96 bytes for any N
- public key is exactly 48 bytes
- single-signer aggregate round-trips

Plus a doctest in the crate root and the `examples/demo.rs` end-to-end.

## Security note

This crate implements the **textbook BLS signature scheme**: hash-to-scalar followed by scalar multiplication of the G2 generator. That construction is simpler than a full [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) hash-to-curve implementation and is **not suitable for production deployments**.

For production:
- Use a vetted BLS library: [`blst`](https://github.com/supranational/blst), [`bls-signatures`](https://github.com/filecoin-project/bls-signatures), or [`bls_signatures_rs`](https://crates.io/crates/bls_signatures_rs)
- Use RFC 9380 hash-to-curve with the recommended domain separation tag
- Use a proof-of-possession or another rogue-key-attack mitigation when aggregating across mutually-distrusting signers on the same message

This repository is a reference implementation for prototyping, audits, and teaching. The trade-offs are called out so you don't ship it to mainnet by accident.

## Dependencies

- [`bls12_381`](https://crates.io/crates/bls12_381) `0.8` — the curve
- [`group`](https://crates.io/crates/group) `0.13` — `Curve` trait
- [`sha2`](https://crates.io/crates/sha2) `0.10` — message hashing
- [`rand_core`](https://crates.io/crates/rand_core) `0.6` — key generation

## License

AGPL-3.0.

---

**Connect:** [LinkedIn](https://www.linkedin.com/in/mirzacausevic/) · [Kinetic Gain](https://kineticgain.com) · [Medium](https://medium.com/@mizcausevic/) · [Skills](https://mizcausevic.com/skills/)
