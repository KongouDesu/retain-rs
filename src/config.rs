use serde::{Serialize, Deserialize};
use serde_json;
use std::fmt::{Debug, Formatter};

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
}

impl Config {
    pub fn from_file<T: AsRef<str>>(path: T) -> Self {
        let contents = std::fs::read(path.as_ref());
        match contents {
            Ok(s) => {
                match serde_json::from_slice(&s) {
                    Ok(cfg) => cfg,
                    Err(_) => Self::default(),
                }
            },
            Err(_) => Self::default(),
        }
    }

    pub fn save_to<T: AsRef<str>>(&self, path: T) -> Result<(), std::io::Error> {
        std::fs::write(path.as_ref(), serde_json::to_vec(self).unwrap())
    }
}