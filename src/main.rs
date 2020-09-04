use rsa::{RSAPrivateKey, RSAPublicKey, pem};

use aias_core::crypto::{DistributedRSAPrivKey};
use aias_core::judge;

extern crate openssl;
use openssl::rsa::{Rsa};

use std::process::{Command, Stdio};


fn generate_distributed_keys() {
    let rsa = Rsa::generate(2048).unwrap();

    let privkey = rsa.private_key_to_pem().unwrap();
    let pubkey = rsa.public_key_to_pem().unwrap();
    

    let privkey = pem::parse(privkey).expect("failed to parse pem");
    let privkey = RSAPrivateKey::from_pkcs1(&privkey.contents).expect("failed to parse pkcs1");

    let pubkey = pem::parse(pubkey).expect("failed to parse pem");
    let pubkey = RSAPublicKey::from_pkcs8(&pubkey.contents).expect("failed to parse pkcs8");

    let d_privkeys = DistributedRSAPrivKey::new(&privkey, &pubkey);

    for d_privey in d_privkeys.private_key_set.private_keys {
        reset_screen();

        let key = serde_json::to_string(&d_privey).unwrap();
        println!("{}", key);

        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
    };
    reset_screen();
}

fn open_stdin() -> String {
    let shares = read_lines_stdin();

    let id_str = judge::open(shares)
        .expect("failed to open Signature");

    id_str
}

fn read_lines_stdin() -> Vec<String> {
    use std::io::{self};

    let stdin = io::stdin();

    let mut v = Vec::new();
    let mut buf = String::new();

    while let Ok(l) = stdin.read_line(&mut buf) {
        if l < 2 { break; }
        v.push(buf.clone());
        buf.clear();
    }

    v
}

fn reset_screen() {
    let mut child = Command::new("reset")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start sed process");
    child.wait()
        .expect("failed to wait child");
}

fn main() {
    let mut args = std::env::args();

    let program = args.next().expect("failed to get program name");
    let command = match args.next() {
        Some(c) => c,
        None => {
            eprintln!("usage: {} [generate | open]", program);
            return
        }
    };

    if command == "generate" {
        generate_distributed_keys();
    } else if command == "open" {
        let id_str = open_stdin();
        println!("id opened: {}", id_str);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn generate() {
        use std::process::Stdio;

        let new_lines: String = std::iter::repeat('\n').take(100).collect();
        println!("{}", new_lines);

        let name = cmd_name();
        Command::new(name)
            .arg("generate")
            .stdin(Stdio::piped())
            .output()
            .expect("failed to execute process");
    }

    #[test]
    #[ignore]
    fn open() {
        use std::fs::File;

        let name = cmd_name();

        let f = File::open("./shares.txt").unwrap();

        let output = Command::new(name)
            .arg("open")
            .stdin(f)
            .output()
            .expect("failed to execute process");

        assert_eq!(String::from_utf8_lossy(&output.stdout), format!("id opened: {}\n", "hogehoge"));
    }

    fn cmd_name() -> String {
        std::env::args().next().unwrap().to_string()
    }
}