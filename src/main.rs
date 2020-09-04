use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, pem, BigUint};

use aias_core::crypto::{DistributedRSAPrivKey, RSAPubKey};

use distributed_rsa::PlainShareSet;
use std::env;

extern crate openssl;
use openssl::rsa::{Rsa};

use std::process::{Command, Stdio};


fn generate_distributed_keys(){
    let rsa = Rsa::generate(2048).unwrap();

    let privkey = rsa.private_key_to_pem().unwrap();
    let pubkey = rsa.public_key_to_pem().unwrap();
    

    let _privkey = pem::parse(privkey).expect("failed to parse pem");
    let _privkey = RSAPrivateKey::from_pkcs1(&_privkey.contents).expect("failed to parse pkcs1");

    let _pubkey = pem::parse(pubkey).expect("failed to parse pem");
    let _pubkey = RSAPrivateKey::from_pkcs8(&_pubkey.contents).expect("failed to parse pkcs8");

    let d_privkeys = DistributedRSAPrivKey::new(&_privkey, &_pubkey);

    for d_privey in d_privkeys.private_key_set.private_keys {
        let key = serde_json::to_string(&d_privey).unwrap();
        println!("{}", key);

        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();

        Command::new("reset")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start sed process");
    };
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
    // let args: Vec<String> = env::args().collect();

    // let query = &args[1];

    // if query == "generate" { 
    //     let (d_pubkey, d_privkey) = generate_distributed_keys();
    //     println!("pubkey\n{}", d_pubkey);

    // }    

    // let plain_share_set = collect_shares();

    // let decrypted = plain_share_set.decrypt();
    // let decrypted_str = String::from_utf8(decrypted.to_bytes_le()).unwrap();

    generate_distributed_keys();
}

#[test]
fn test() {
    let message_str = "hogehoge".to_string();

    let plain_share_set = collect_shares();

    let decrypted = plain_share_set.decrypt();
    let decrypted_str = String::from_utf8(decrypted.to_bytes_le()).unwrap();

    println!("message:\t'{}'", message_str);
    println!("decrypted:\t'{}'", decrypted_str);

    assert_eq!(message_str, decrypted_str);
}
