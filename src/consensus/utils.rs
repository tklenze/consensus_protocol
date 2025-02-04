use sha2::{Digest, Sha256};
pub type Hash = [u8; 32];

pub struct Crypto;

pub type Signature = (u64, Vec<u8>);

impl Crypto {
    /// Converts a variable into bytes
    pub fn var_to_bytes(x: usize) -> Vec<u8> {
        x.to_le_bytes().to_vec()
    }

    /// Hashes a given byte array
    pub fn hash(x: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(x);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Converts a variable into bytes and hashes the result
    pub fn sha256_var(x: usize) -> Hash {
        Crypto::hash(&Crypto::var_to_bytes(x))
    }
    
    /// Shorts a given hash to fit into a usize
    pub fn short_hash(x: &[u8]) -> usize {
        let short_hash = &x[..8];
        usize::from_le_bytes(short_hash.try_into().unwrap())
    }

    /// FIXME Dummy crypto!
    pub fn sign(signer: u64, x: &[u8]) -> Signature {
        (signer, x.to_vec())
    }

    /// FIXME Dummy crypto!
    pub fn check_signature(signer: u64, plaintext: &[u8], signature: &Signature) -> bool {
        signature == &Crypto::sign(signer, plaintext)
    }
}

pub struct Debug;

impl Debug {
    /// Used for debugging purposes

    pub fn dbg(m: &str, id: usize, type_: Option<&str>) {
        let colors = [
            "\x1b[0m",     // default
            "\x1b[32m#0 ", // green, used for node 0
            "\x1b[33m#1 ", // yellow, used for node 1
            "\x1b[34m#2 ", // blue, used for node 2
            "\x1b[35m#3 ", // magenta, used for node 3
        ];

        let mut message = m.to_string();
        if let Some(type_) = type_ {
            match type_ {
                "ERROR" => {
                    message = format!("\x1b[1;31m !ERROR! {}", m);
                }
                "SOUDNESS_ERROR" => {
                    message = format!("\x1b[1;31m !SOUDNESS_ERROR! {}", m);
                }
                "ATTACK" => message = format!("\x1b[31m !ATTACK! {}", m),
                "USER_ATTACK" => message = format!("\x1b[31m USER ATTACK {}", m),
                "NETWORK" => message = format!("\x1b[1;34m NETWORK {}", m),
                _ => {}
            }
        }

        let color_code: &str = if id < colors.len() {
            colors[id]
        } else {
            colors[0]
        };

        println!("{}{}{}", color_code, message, "\x1b[0m");
    }
}
