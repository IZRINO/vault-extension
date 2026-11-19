use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::pkcs8::DecodePublicKey;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use vault_passkeys::{Ceremony, Passkey, validate_rp};

#[test]
fn private_suffix_and_sibling_origins_do_not_authorize_signing() {
    assert!(validate_rp("https://accounts.example.com", "example.com").is_ok());
    assert!(validate_rp("https://example.com.invalid", "example.com").is_err());
    assert!(validate_rp("https://login.github.io", "github.io").is_err());
    assert!(validate_rp("https://login.example.co.uk", "co.uk").is_err());
    assert!(validate_rp("http://accounts.example.com", "example.com").is_err());
}

#[test]
fn verifier_checks_both_algorithms_and_real_flags_against_server_challenge() {
    for algorithm in [-7, -8] {
        let origin = "https://login.example.com";
        let rp_id = "example.com";
        let challenge = B64.encode([11u8; 32]);
        let operation = Ceremony::new(origin, rp_id, &challenge);
        let (key, register) = Passkey::register(&operation, &[42; 32], "fixture-account", algorithm, true, false).unwrap();
        let authenticator_data = B64.decode(register.authenticator_data.as_deref().unwrap()).unwrap();
        assert_eq!(authenticator_data[..32], Sha256::digest(rp_id)[..]);
        assert_eq!(authenticator_data[32], 0x45 | 0x08);
        assert_eq!(&authenticator_data[33..37], &[0; 4]);
        assert_eq!(register.public_key_algorithm, Some(algorithm));
        let assertion_challenge = B64.encode([57u8; 32]);
        let assertion = key.assert(&Ceremony::new(origin, rp_id, &assertion_challenge), false, true, 0).unwrap();
        let auth = B64.decode(assertion.authenticator_data.as_deref().unwrap()).unwrap();
        assert_eq!(auth[32], 0x19);
        let json = B64.decode(&assertion.client_data_json).unwrap();
        let data: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(data["challenge"], assertion_challenge);
        assert_eq!(data["origin"], origin);
        assert_eq!(data["type"], "webauthn.get");
        assert_eq!(assertion.id, register.id);
        let signed = [auth.as_slice(), &Sha256::digest(json)].concat();
        let signature = B64.decode(assertion.signature.as_deref().unwrap()).unwrap();
        let public = B64.decode(register.public_key.as_deref().unwrap()).unwrap();
        if algorithm == -7 {
            VerifyingKey::from_public_key_der(&public).unwrap().verify(&signed, &Signature::from_der(&signature).unwrap()).unwrap();
        } else {
            ed25519_dalek::VerifyingKey::from_public_key_der(&public).unwrap().verify_strict(&signed,
                &ed25519_dalek::Signature::from_slice(&signature).unwrap()).unwrap();
        }
    }
}

#[test]
fn restored_counters_use_trusted_highest_or_suspend_incrementing_keys() {
    use vault_core::model::{CredentialData, VaultItem};
    use vault_passkeys::bundle::{CounterEvidence, read, write};
    let challenge = B64.encode([11u8; 32]);
    let operation = Ceremony::new("https://login.example.com", "example.com", &challenge);
    for algorithm in [-7, -8] {
        let (mut counted, _) = Passkey::register(&operation, &[42; 32], "fixture", algorithm, true, true).unwrap();
        counted.count = 2;
        let (zero, _) = Passkey::register(&operation, &[42; 32], "fixture", algorithm, true, false).unwrap();
        let yesterday = write(&[counted.clone(), zero]).unwrap();
        counted.count = 13;
        let mut local = VaultItem::from_json_str(r#"{"title":"Fixture","data":{"kind":"login"}}"#).unwrap();
        let CredentialData::Login(login) = &mut local.data else { panic!() };
        login.passkey_data = write(&[counted]).unwrap();
        let known = CounterEvidence::from_items(&[local]).unwrap();
        for is_pack in [false, true] {
            let restored = read(&known.restore(&yesterday, is_pack).unwrap()).unwrap();
            assert_eq!((restored[0].count, restored[0].count_unverified), (13, false));
            assert_eq!((restored[1].count, restored[1].count_unverified), (0, false));
            let unverified = read(&CounterEvidence::default().restore(&yesterday, is_pack).unwrap()).unwrap();
            assert!(unverified[0].count_unverified);
            assert!(!unverified[1].count_unverified);
        }
    }
}
