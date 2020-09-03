use rsa::{RSAPrivateKey, RSAPublicKey, BigUint};

use aias_core::crypto::{DistributedRSAPrivKey, RSAPubKey};

fn main() {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048;
    let privkey = RSAPrivateKey::new(&mut rng, bits)
        .expect("failed to generate private key");
    let pubkey = RSAPublicKey::from(&privkey);

    let d_privkey = DistributedRSAPrivKey::new(&privkey, &pubkey);
    let d_pubkey = RSAPubKey { public_key: pubkey };

    let message = "hogehoge";
    let message_biguint = BigUint::from_bytes_le(message.as_bytes());

    let encrypted = d_pubkey.encrypt_core(message_biguint);

    let decrypted = d_privkey.decrypt_core(encrypted);
    let decrypted_str = String::from_utf8(decrypted.to_bytes_le()).unwrap();

    println!("message:\t'{}'", message);
    println!("decrypted:\t'{}'", decrypted_str);

    assert_eq!(message, decrypted_str);
}
