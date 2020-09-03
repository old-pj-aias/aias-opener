use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};

fn main() {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048;
    let privkey = RSAPrivateKey::new(&mut rng, bits)
        .expect("failed to generate private key");
    let pubkey = RSAPublicKey::from(&privkey);

    let message = "hogehoge";

    let cipher = pubkey.encrypt(&mut rng, rsa::PaddingScheme::PKCS1v15Encrypt, message.as_bytes())
        .expect("failed to encrypt message");

    let decrypted = privkey.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &cipher)
        .expect("failed to decrypt cipher");
    let decrypted_str = String::from_utf8(decrypted).unwrap();

    println!("message:\t'{}'", message);
    println!("decrypted:\t'{}'", decrypted_str);

    assert_eq!(message, decrypted_str);
}
