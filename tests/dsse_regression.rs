use packslip::dsse::{Envelope, EnvelopeSignature, IN_TOTO_PAYLOAD_TYPE};
use packslip::minisign::{SecretKey, key_id_hex};

#[test]
fn a_bad_entry_cannot_hide_a_valid_signature() {
    let key = SecretKey::from_seed([5; 32]);
    let public = key.public_key();
    let payload = br#"{"subject":[]}"#;
    let mut envelope = Envelope::sign(IN_TOTO_PAYLOAD_TYPE, payload, &key);
    envelope.signatures.insert(
        0,
        EnvelopeSignature {
            keyid: key_id_hex(&public.key_id),
            sig: "!!!!".into(),
        },
    );

    assert_eq!(envelope.verify(&public).unwrap(), payload);
}

#[test]
fn a_key_id_hint_cannot_hide_a_valid_signature() {
    let key = SecretKey::from_seed([5; 32]);
    let public = key.public_key();
    let payload = br#"{"subject":[]}"#;
    let mut envelope = Envelope::sign(IN_TOTO_PAYLOAD_TYPE, payload, &key);
    envelope.signatures[0].keyid = "wrong-key".into();

    assert_eq!(envelope.verify(&public).unwrap(), payload);

    envelope.payload_type = "text/plain".into();
    assert!(envelope.verify(&public).is_err());
}
