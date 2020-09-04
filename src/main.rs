use rsa::{RSAPrivateKey, RSAPublicKey, BigUint, pem};

use aias_core::crypto::{DistributedRSAPrivKey};
use aias_core::judge;
use distributed_rsa::DistributedRSAPrivateKey;
use fair_blind_signature::Signature;

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

    let d_privkeys = DistributedRSAPrivKey::new(&privkey, &pubkey, 3);

    for d_privey in d_privkeys.private_key_set.private_keys {
        reset_screen();

        let key = serde_json::to_string(&d_privey).unwrap();
        println!("{}", key);

        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
    };
    reset_screen();
}

fn create_share_stdin(secret_key_file: &str) {
    use std::fs::File;
    use std::io;

    let mut f = File::open(secret_key_file)
        .expect("failed to read secret key");
    let secret_key_str = read_content(&mut f, secret_key_file);
    let secret_key: DistributedRSAPrivateKey = serde_json::from_str(&secret_key_str)
        .expect("failed to parse secret key");

    let mut stdin = io::stdin();
    let fbs_str = read_content(&mut stdin, "stdin");
    let fbs: Signature = serde_json::from_str(&fbs_str)
        .expect("failed to parse cipher");
    let encrypted_id_str = fbs.encrypted_id.v[0].clone();
    let encrypted_id: BigUint = serde_json::from_str(&encrypted_id_str).unwrap();
    
    let plain_share = secret_key.generate_share(encrypted_id);

    let share_json = serde_json::to_string(&plain_share)
        .expect("failed to parse share");
    
    println!("{}", share_json);
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

fn read_content<R: std::io::Read>(src: &mut R, src_name: &str) -> String {
    let mut buf = String::new();
    match src.read_to_string(&mut buf) {
        Ok(0) => {
            panic!("Unexpected EOF reading {}", src_name);
        },
        Err(e) => {
            panic!("failed to read {}: {}", src_name, e);
        },
        _ => ()
    }

    return buf;
}

fn reset_screen() {
    let mut child = Command::new("reset")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start sed process");
    child.wait()
        .expect("failed to wait child");
}

fn main() -> Result<(), ()> {
    let mut args = std::env::args();

    // ignore program name (argv[0])
    args.next().expect("failed to get program name");
    let command = get_next(&mut args);

    if command == "generate" {
        let q = get_next(&mut args);
        if q == "key" {
            generate_distributed_keys();
        } else if q == "share" {
            let secret_key = get_next(&mut args);
            create_share_stdin(&secret_key);
        } else {
            usage_exit();
        }
    } else if command == "open" {
        let id_str = open_stdin();
        println!("id opened: {}", id_str);
    }

    Ok(())
}

fn get_next<T: Iterator>(i: &mut T) -> T::Item {
    match i.next() {
        Some(c) => c,
        None => usage_exit(),
    }
}

fn usage_exit() -> ! {
    let mut args = std::env::args();
    eprintln!("usage: {} [open | generate [key | share]]", args.next().unwrap());
    panic!();
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