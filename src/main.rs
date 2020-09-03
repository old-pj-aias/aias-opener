use rsa::{RSAPrivateKey, RSAPublicKey, BigUint};

use aias_core::crypto::{DistributedRSAPrivKey, RSAPubKey};

use distributed_rsa::PlainShareSet;


fn generate_distributed_keys() -> (RSAPubKey, DistributedRSAPrivKey) {
    let mut rng = rand::rngs::OsRng;

    let bits = 2048;

    let private_key = RSAPrivateKey::new(&mut rng, bits)
        .expect("failed to generate private key");
    let public_key = RSAPublicKey::from(&private_key);

    let d_privkey = DistributedRSAPrivKey::new(&private_key, &public_key);
    let d_pubkey = RSAPubKey { public_key: public_key };

    (d_pubkey, d_privkey)
}

#[allow(dead_code)]
fn generate_shares() -> PlainShareSet {
    use std::fs::File;
    use std::io::Write;

    let message_str = "hogehoge".to_string();
    let message = message_str.as_bytes();
    let message_biguint = BigUint::from_bytes_le(message);

    let (d_pubkey, d_privkey) = generate_distributed_keys();

    let c = d_pubkey.encrypt_core(message_biguint);

    let priv_keys = d_privkey.private_key_set.private_keys;

    let mut shares = Vec::new();

    let mut f = File::create("shares.txt")
        .unwrap();
    for k in &priv_keys {

        // collect plain share if its owner agreed
        if true {
            let share = k.generate_share(c.clone());

            let share_str = serde_json::to_string(&share).unwrap();
            f.write_all(share_str.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();

            shares.push(share);
        }
    }

    let plain_share_set = PlainShareSet { plain_shares: shares };

    return plain_share_set;
}

fn collect_shares() -> PlainShareSet {
    use std::io::{self};

    let stdin = io::stdin();

    let mut plain_shares = Vec::new();
    let mut buf = String::new();

    while let Ok(l) = stdin.read_line(&mut buf) {
        if l < 2 { break; }

        let share = serde_json::from_str(&buf)
            .expect("failed to parse json");

        plain_shares.push(share);
        buf.clear();
    }

    PlainShareSet { plain_shares }
}

fn main() {
    let message_str = "hogehoge".to_string();

    let plain_share_set = collect_shares();

    let decrypted = plain_share_set.decrypt();
    let decrypted_str = String::from_utf8(decrypted.to_bytes_le()).unwrap();

    println!("message:\t'{}'", message_str);
    println!("decrypted:\t'{}'", decrypted_str);

    assert_eq!(message_str, decrypted_str);
}
