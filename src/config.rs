use serde::{Serialize, Deserialize};
use serde_json;
use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

// To be double-plus-sure we do not re-use nonces, we will pre-allocate them in blocks
// Every time we allocate a new block, we store the end of the block and write it to disk
// This way we will not re-use nonces even if interrupted.
//
// Example, BLOCK_SIZE = 4096, nonce_alloc = 4096, nonce_ctr = 4000 and we ask for 400 nonces
// We cannot fit that in our block, so we must allocate a new one
// Now, nonce_alloc += BLOCK_SIZE -> 8192. nonce_ctr -> 4400.
// The '8192' was synced to disk and is what will be read next time
// If we do not use the remaining nonces, they are lost. With 128 bits we will never run out in practice
//
// We can upload <encryption::DATA_LENGTH * NONCE_PREALLOC_AMOUNT> bytes per save-to-disk
const NONCE_PREALLOC_AMOUNT: u128 = 65536;
// (8192-16) * 65536 = 535822336 (~535MB)


#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub app_key_id: Option<String>,
    pub app_key: Option<String>,
    pub bucket_name: Option<String>,
    pub backup_list: Option<String>, // Path to backup list

    // Whether or not encryption is enabled
    pub encrypt: Option<bool>,
    // Path key-file. Used only if encryption is enabled
    pub secret_key: Option<String>,
    // End of current nonce-allocation-block
    nonce_alloc: u128,
    #[serde(skip)]
    pub location: String, // The location of the config, s.t. it can save itself
    #[serde(skip)]
    nonce_ctr: u128,
}

impl Config {
    pub fn is_configured(&self) -> Result<(),String> {
        if self.app_key_id.is_none() { return Err("App Key ID is missing".to_string()) };
        if self.app_key.is_none() { return Err("App Key is missing".to_string()) };
        if self.bucket_name.is_none() { return Err("Bucket Name is missing".to_string()) };
        if self.backup_list.is_none() { return Err("File List Path is missing".to_string()) };
        if self.encrypt.is_none() { return Err("You must explicitly enable or disable encryption".to_string()) };
        // Secret key only needs to be set if encryption is on
        if self.encrypt.is_some() && self.encrypt.unwrap() == true {
            if self.secret_key.is_none() { return Err("No secret key configured".to_string()) };
        }
        Ok(())
    }

    pub fn save(&self) {
        std::fs::write(&self.location,serde_json::to_string(self).unwrap()).unwrap();
    }

    pub fn from_file<T: AsRef<str>>(path: T) -> Self {
        let contents = std::fs::read(path.as_ref());
        let mut cfg = match contents {
            Ok(s) => {
                match serde_json::from_slice(&s) {
                    Ok(cfg) => cfg,
                    Err(_) => Self::default(),
                }
            },
            Err(_) => Self::default(),
        };
        cfg.location = path.as_ref().to_string();
        cfg.nonce_ctr = cfg.nonce_alloc;
        cfg
    }

    pub fn save_to<T: AsRef<str>>(&self, path: T) -> Result<(), std::io::Error> {
        std::fs::write(path.as_ref(), serde_json::to_vec(self).unwrap())
    }

    // Consume the specified amount of nonces
    // Returns the starting nonce that the consumer should use
    // Behind the scenes, this will handle pre-allocating and saving to disk
    pub fn consume_nonces(&mut self, amount: u128) -> u128 {
        let start = self.nonce_ctr;
        self.nonce_ctr += amount;
        let mut write = false;
        // In case we need to allocate a lot or pre-alloc is small, we may need multiple blocks
        while self.nonce_ctr >= self.nonce_alloc {
            self.nonce_alloc += NONCE_PREALLOC_AMOUNT;
            write = true;
        }
        if write {
            self.save();
        }

        start
    }
}