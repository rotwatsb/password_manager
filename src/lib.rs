extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher, SipHasher};
use std::iter;

use crypto::pbkdf2;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::aead::{AeadEncryptor, AeadDecryptor};

use rand::{OsRng, Rng};

use rustc_serialize::hex::{ToHex, FromHex};
use rustc_serialize::json;

#[derive(RustcDecodable, RustcEncodable, Hash)]
struct PortableKeychain {
    secure_map: BTreeMap<String, String>,
    domain_salts: BTreeMap<String, String>,
    password_salts: BTreeMap<String, String>,
    master_salt: String,
    checksums: Vec<u64>,
}

pub struct Keychain {
    enc_key: [u8; 32],
    dm_encoder1: Hmac<Sha256>,               // for secure_map domains
    dm_encoder2: Hmac<Sha256>,               // for domain_salts domains
    dm_encoder3: Hmac<Sha256>,               // for password_salts domains
    secure_map: BTreeMap<String, String>,
    domain_salts: BTreeMap<String, String>,
    password_salts: BTreeMap<String, String>,
    master_salt: String,
    rng: OsRng,
}

struct KeyGen {
    master_key: Vec<u8>,
    master_hasher: Sha256,
    key_count: u8,
}

impl KeyGen {
    fn new(password: &str, salt: &Vec<u8>) -> KeyGen {

        let hasher = Sha256::new();
        let mut hmac = Hmac::new(hasher, password.as_bytes());
        let mut master: [u8; 32] = [0u8; 32];
        
        pbkdf2::pbkdf2(&mut hmac, &salt[..], 10000, &mut master);

        KeyGen {
            master_key: master.iter().cloned().collect::<Vec<u8>>(),
            master_hasher: hasher,
            key_count: 0,
        }
    }
}

impl Iterator for KeyGen {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<[u8; 32]> {
        let mut next_key: [u8; 32] = [0; 32];
        self.master_hasher.reset();
        self.master_key.push(self.key_count);
        self.master_hasher.input(&self.master_key[..]);
        self.master_hasher.result(&mut next_key);
        self.master_key.pop();
        self.key_count += 1;
        Some(next_key)
    }
}

impl Keychain {

    pub fn init(password: &str) -> Keychain {

        let mut kc: Keychain = make_keychain(password, None, None, None, None);
        kc.set("magicmagicmagic".to_string(), "magicmagicmagic".to_string());

        kc
    }

    fn domain_found(&mut self, domain: String) -> bool {
        let mut dm_salt_key: Vec<u8> = vec![0; 32];
        
        set_encoded_dm(&mut self.dm_encoder2, &domain.into_bytes(),
                       &mut dm_salt_key);
        
        if let Some(x) = self.domain_salts.get(&dm_salt_key[..].to_hex())
        { true } else { false }
    }

    pub fn get(&mut self, domain: String) -> Option<String> {
        if !self.domain_found(domain.clone()) { return None; }

        let mut dm_salt_key: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder2, &(domain.clone().into_bytes()),
                       &mut dm_salt_key);

        let mut pw_salt_key: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder3, &(domain.clone().into_bytes()),
                       &mut pw_salt_key);

        let dm_salt: Vec<u8> = self.domain_salts.get(&dm_salt_key[..].to_hex())
            .unwrap().from_hex().unwrap();
        
        let pw_salt: Vec<u8> = self.password_salts.get(&pw_salt_key[..].to_hex())
            .unwrap().from_hex().unwrap();
        
        let mut dm_salted: Vec<u8> = domain.into_bytes();
        dm_salted.extend(dm_salt.iter().cloned());
        
        let mut encoded_dm: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder1, &dm_salted, &mut encoded_dm);
        
        let mut encoded_pw: Vec<u8> = self.secure_map.get(&encoded_dm[..].to_hex())
            .unwrap().from_hex().unwrap();

        let mut decoded_pw: Vec<u8> = Vec::new();
        set_decoded_pt(&self.enc_key, &pw_salt, &mut encoded_pw, &mut decoded_pw);
        
        Some(String::from_utf8(decoded_pw).unwrap())
    }

    pub fn remove(&mut self, domain: String) -> bool {
        if !self.domain_found(domain.clone()) { return false; }

        let mut dm_salt_key: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder2, &(domain.clone().into_bytes()),
                       &mut dm_salt_key);

        let mut pw_salt_key: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder3, &(domain.clone().into_bytes()),
                       &mut pw_salt_key);

        let dm_salt: Vec<u8> = self.domain_salts.get(&dm_salt_key[..].to_hex())
            .unwrap().from_hex().unwrap();

        let mut dm_salted: Vec<u8> = domain.into_bytes();
        dm_salted.extend(dm_salt.iter().cloned());

        let mut encoded_dm: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder1, &dm_salted, &mut encoded_dm);

        let rmd_dm_salt = self.domain_salts.remove(&dm_salt_key[..].to_hex());
        let rmd_pw_salt = self.password_salts.remove(&pw_salt_key[..].to_hex());
        let rmd_entry = self.secure_map.remove(&encoded_dm[..].to_hex());

        true
    }

    pub fn set(&mut self, domain: String, password: String) {
        
        let pw_salt: Vec<u8> = self.rng.gen_iter().take(12).collect::<Vec<u8>>();
        let dm_salt: Vec<u8> = self.rng.gen_iter().take(16).collect::<Vec<u8>>();

        let mut dm_salted: Vec<u8> = domain.clone().into_bytes();
        dm_salted.extend(dm_salt.iter().cloned());

        let mut encoded_dm1: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder1, &dm_salted, &mut encoded_dm1);

        let mut encoded_dm2: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder2, &(domain.clone().into_bytes()),
                       &mut encoded_dm2);

        let mut encoded_dm3: Vec<u8> = vec![0; 32];
        set_encoded_dm(&mut self.dm_encoder3, &(domain.clone().into_bytes()),
                       &mut encoded_dm3);

        let mut encoded_pw: Vec<u8> = iter::repeat(0).take(password.len()).collect();
        set_encoded_ct(&self.enc_key, &pw_salt, password, &mut encoded_pw);
        
        self.secure_map.insert(encoded_dm1[..].to_hex(), encoded_pw[..].to_hex());
        self.domain_salts.insert(encoded_dm2[..].to_hex(), dm_salt[..].to_hex());
        self.password_salts.insert(encoded_dm3[..].to_hex(), pw_salt[..].to_hex());
    }

    pub fn dump(&mut self) -> String {

        let mut hasher = SipHasher::new();

        self.secure_map.hash(&mut hasher); 
        let h1: u64 = hasher.finish();
        
        self.domain_salts.hash(&mut hasher);
        let h2: u64 = hasher.finish();

        self.password_salts.hash(&mut hasher);
        let h3: u64 = hasher.finish();

              
        let pkc = PortableKeychain {
            secure_map: self.secure_map.clone(),
            domain_salts: self.domain_salts.clone(),
            password_salts: self.password_salts.clone(),
            master_salt: self.master_salt.clone(),
            checksums: vec![h1, h2, h3],
        };

        json::encode(&pkc).unwrap()
    }

    pub fn load(password: &str, repr: String) -> Option<Keychain> {

        let pkc_opt: Result<PortableKeychain, _> = json::decode(&repr);


        if let Ok(pkc) = pkc_opt {
            let mut hasher = SipHasher::new();

            if hash_ok(&mut hasher, &mut pkc.secure_map.clone(), pkc.checksums[0]) &&
                hash_ok(&mut hasher, &mut pkc.domain_salts.clone(), pkc.checksums[1]) &&
                hash_ok(&mut hasher, &mut pkc.password_salts.clone(), pkc.checksums[2]) {
                    let mut kc: Keychain =
                        make_keychain(password,
                                      Some(pkc.master_salt.from_hex().unwrap()),
                                      Some(pkc.secure_map), Some(pkc.domain_salts),
                                      Some(pkc.password_salts));

                    if let Some(value) = kc.get("magicmagicmagic".to_string()) {
                        if value == "magicmagicmagic".to_string()
                        { Some(kc) } else { None }
                    }
                    else { None }
                }
            else { None }
        }
        else { None }
    }
}

fn hash_ok<T>(hasher: &mut SipHasher, data: &mut T, checksum: u64) -> bool
    where T: Hash {
    data.hash(hasher);
    hasher.finish() == checksum
}

fn make_keychain(password: &str, salt: Option<Vec<u8>>,
                 sm: Option<BTreeMap<String, String>>,
                 dm: Option<BTreeMap<String, String>>,
                 pm: Option<BTreeMap<String, String>>) -> Keychain {

    let mut g: OsRng = OsRng::new().unwrap();

    let ms = if let Some(s) = salt { s }
    else { g.gen_iter().take(16).collect::<Vec<u8>>() };

    let mut kg: KeyGen = KeyGen::new(password, &ms);

    Keychain {
        enc_key: kg.next().unwrap(),
        dm_encoder1: Hmac::new(Sha256::new(), &kg.next().unwrap()),
        dm_encoder2: Hmac::new(Sha256::new(), &kg.next().unwrap()),
        dm_encoder3: Hmac::new(Sha256::new(), &kg.next().unwrap()),
        secure_map: (if let Some(m) = sm { m } else { BTreeMap::new() }),
        domain_salts: (if let Some(m) = dm { m } else { BTreeMap::new() }),
        password_salts: (if let Some(m) = pm { m } else { BTreeMap::new() }),
        master_salt: ms.to_hex(),
        rng: g,
    }
}

fn set_decoded_pt(key: &[u8; 32], salt: &Vec<u8>,
                  cipher_text: &mut Vec<u8>, plain_text: &mut Vec<u8>) {

    let cipher_and_tag_len = cipher_text.len();
    
    let a_tag: Vec<u8> = cipher_text.split_off(cipher_and_tag_len - 16);
    
    plain_text.extend(iter::repeat(0).take(cipher_text.len()).collect::<Vec<u8>>());
    
    let aad: [u8; 32] = [0; 32];
    let mut decipher = AesGcm::new(KeySize::KeySize256, key, &salt[..], &aad[..]);

    let result = decipher.decrypt(&cipher_text[..], &mut plain_text[..], &a_tag[..]);
}

fn set_encoded_ct(key: &[u8; 32], salt: &Vec<u8>,
                  plain_text: String, cipher_text: &mut Vec<u8>) {
    
    let aad: [u8; 32] = [0; 32];
    let mut a_tag: Vec<u8> = iter::repeat(0).take(16).collect();
    let mut cipher = AesGcm::new(KeySize::KeySize256, key, &salt[..], &aad[..]);

    cipher.encrypt(&plain_text.as_bytes()[..], &mut cipher_text[..], &mut a_tag[..]);
    cipher_text.extend(a_tag);
}

fn set_encoded_dm(encoder: &mut Hmac<Sha256>, dm: &Vec<u8>, encoded_dm: &mut Vec<u8>) {
    encoder.input(&dm[..]);
    encoder.raw_result(&mut encoded_dm[..]);
    encoder.reset();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

