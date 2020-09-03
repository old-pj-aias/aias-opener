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

fn main() {
    let (d_pubkey, d_privkey) = generate_distributed_keys();

    let message_str = "hogehoge".to_string();
    let message = message_str.as_bytes();
    let message_biguint = BigUint::from_bytes_le(message);

    let c = d_pubkey.encrypt_core(message_biguint);

    let priv_keys = d_privkey.private_key_set.private_keys;

    let mut shares = Vec::new();

    for k in &priv_keys {
        // collect plain share if its owner agreed
        if true {
            let share = k.generate_share(c.clone());
            shares.push(share);
        }
    }

    let plain_share_set = PlainShareSet { plain_shares: shares };

    let decrypted = plain_share_set.decrypt();
    let decrypted_str = String::from_utf8(decrypted.to_bytes_le()).unwrap();

    println!("message:\t'{}'", message_str);
    println!("decrypted:\t'{}'", decrypted_str);

    assert_eq!(message_str, decrypted_str);
}
