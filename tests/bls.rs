use bls_attestation_broker::{AttestationBroker, Attestor};

#[test]
fn single_signer_verifies() {
    let mut rng = rand::thread_rng();
    let alice = Attestor::generate(&mut rng);
    let message = b"agent foo authorized at 2026-05-12T05:00:00Z";

    let mut broker = AttestationBroker::new(message);
    broker.add(&alice);
    let att = broker.finalize();

    assert!(att.verify(&[alice.public_key()], message));
}

#[test]
fn three_signers_verify_as_aggregate() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let b = Attestor::generate(&mut rng);
    let c = Attestor::generate(&mut rng);
    let message = b"tenants {a,b,c} approve MCP tool: ticket-create";

    let mut broker = AttestationBroker::new(message);
    broker.add(&a);
    broker.add(&b);
    broker.add(&c);
    let att = broker.finalize();

    assert_eq!(att.signer_count, 3);
    assert!(att.verify(&[a.public_key(), b.public_key(), c.public_key()], message));
}

#[test]
fn wrong_signer_set_fails_verification() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let b = Attestor::generate(&mut rng);
    let imposter = Attestor::generate(&mut rng);
    let message = b"foo";

    let mut broker = AttestationBroker::new(message);
    broker.add(&a);
    broker.add(&b);
    let att = broker.finalize();

    // Replacing b with an imposter must fail.
    assert!(!att.verify(&[a.public_key(), imposter.public_key()], message));
}

#[test]
fn wrong_message_fails_verification() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let b = Attestor::generate(&mut rng);

    let mut broker = AttestationBroker::new(b"original message");
    broker.add(&a);
    broker.add(&b);
    let att = broker.finalize();

    assert!(!att.verify(&[a.public_key(), b.public_key()], b"tampered message"));
}

#[test]
fn signer_count_mismatch_fails_verification() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let b = Attestor::generate(&mut rng);
    let c = Attestor::generate(&mut rng);
    let message = b"three-signer attestation";

    let mut broker = AttestationBroker::new(message);
    broker.add(&a);
    broker.add(&b);
    broker.add(&c);
    let att = broker.finalize();

    // Provide only 2 of the 3 keys.
    assert!(!att.verify(&[a.public_key(), b.public_key()], message));
}

#[test]
fn aggregate_signature_is_96_bytes() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let b = Attestor::generate(&mut rng);
    let c = Attestor::generate(&mut rng);

    let mut broker = AttestationBroker::new(b"any message");
    broker.add(&a);
    broker.add(&b);
    broker.add(&c);
    let att = broker.finalize();

    let bytes = att.aggregate_signature.to_bytes();
    assert_eq!(bytes.len(), 96);
}

#[test]
fn public_key_is_48_bytes() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let pk = a.public_key();
    assert_eq!(pk.to_bytes().len(), 48);
}

#[test]
fn single_signer_aggregate_round_trips() {
    let mut rng = rand::thread_rng();
    let a = Attestor::generate(&mut rng);
    let message = b"single attestor case";

    let mut broker = AttestationBroker::new(message);
    broker.add(&a);
    let att = broker.finalize();
    // A one-signer aggregate is just the single signer's signature; it must verify.
    assert!(att.verify(&[a.public_key()], message));
}
