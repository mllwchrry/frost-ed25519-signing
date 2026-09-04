// Cross-check oracle: ed25519-dalek verdicts for the interop harness.
//
// Reads the cross-check cases as JSON on stdin (produced by run_crosscheck.py;
// schema is the Doc/Case structs below), and per case reports two booleans:
//
//   dalek_verify:        VerifyingKey::verify, the permissive Verifier-trait path.
//   dalek_verify_strict: VerifyingKey::verify_strict, the cofactorless form that
//                        rejects small-order keys and nonces; the equation Solana
//                        enforces via this same crate.
//
// The harness feeds valid signatures and checks both come back true. A public key
// or signature that will not even decode yields (false, false).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::io::Read;

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    msg: String,
    pubkey: String,
    sig: String,
}

#[derive(serde::Deserialize)]
struct Doc {
    cases: Vec<Case>,
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let doc: Doc = serde_json::from_str(&input).expect("parse cases JSON");

    let mut out = serde_json::Map::new();
    for c in doc.cases {
        let msg = hex::decode(&c.msg).expect("msg hex");
        let pkb = hex::decode(&c.pubkey).expect("pubkey hex");
        let sigb = hex::decode(&c.sig).expect("sig hex");

        let (mut verify, mut verify_strict) = (false, false);
        if let (Ok(pk_arr), Ok(sig_arr)) =
            (<[u8; 32]>::try_from(pkb.as_slice()), <[u8; 64]>::try_from(sigb.as_slice()))
        {
            if let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) {
                let sig = Signature::from_bytes(&sig_arr);
                verify = vk.verify(&msg, &sig).is_ok();
                verify_strict = vk.verify_strict(&msg, &sig).is_ok();
            }
        }

        let mut m = serde_json::Map::new();
        m.insert("dalek_verify".into(), verify.into());
        m.insert("dalek_verify_strict".into(), verify_strict.into());
        out.insert(c.id, serde_json::Value::Object(m));
    }

    println!(
        "{}",
        serde_json::to_string(&serde_json::Value::Object(out)).unwrap()
    );
}
