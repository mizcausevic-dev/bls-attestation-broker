//! Three tenants sign the same agent-authorization message; the
//! broker aggregates their signatures into one 96-byte attestation
//! and the verifier checks it against the sum of their public keys.

use bls_attestation_broker::{AttestationBroker, Attestor};

fn main() {
    let mut rng = rand::thread_rng();

    let tenant_a = Attestor::generate(&mut rng);
    let tenant_b = Attestor::generate(&mut rng);
    let tenant_c = Attestor::generate(&mut rng);

    let message =
        b"agent='customer-support-tier-1' tool='ticket-create' approved=2026-05-12T05:00:00Z";
    println!(
        "message ({} bytes): {}",
        message.len(),
        std::str::from_utf8(message).unwrap()
    );

    let mut broker = AttestationBroker::new(message);
    broker.add(&tenant_a);
    broker.add(&tenant_b);
    broker.add(&tenant_c);

    let attestation = broker.finalize();
    println!(
        "\naggregated {} attestor signatures into one signature",
        attestation.signer_count
    );
    println!(
        "aggregate signature: {} bytes ({})",
        attestation.aggregate_signature.to_bytes().len(),
        hex::encode(&attestation.aggregate_signature.to_bytes()[..16])
    );

    let signers = [
        tenant_a.public_key(),
        tenant_b.public_key(),
        tenant_c.public_key(),
    ];

    let ok = attestation.verify(&signers, message);
    println!("\nverification: {}", if ok { "ACCEPT" } else { "REJECT" });

    // Demonstrate failure modes.
    let imposter = Attestor::generate(&mut rng);
    let bad_signers = [
        tenant_a.public_key(),
        imposter.public_key(),
        tenant_c.public_key(),
    ];
    let bad_ok = attestation.verify(&bad_signers, message);
    println!(
        "verification with imposter for tenant_b: {}",
        if bad_ok {
            "ACCEPT"
        } else {
            "REJECT (expected)"
        }
    );

    let tampered_ok = attestation.verify(&signers, b"tampered message");
    println!(
        "verification of tampered message: {}",
        if tampered_ok {
            "ACCEPT"
        } else {
            "REJECT (expected)"
        }
    );
}
