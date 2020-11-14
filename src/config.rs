use serde::{Serialize, Deserialize};
use serde_json;
use std::fmt::{Debug, Formatter};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub app_key_id: Option<String>,
    pub app_key: Option<String>,
    pub bucket_name: Option<String>,

    // Whether or not encryption is enabled
    pub encrypt: Option<bool>,
    // Secret key or path to key-file. Used only in encryption is enabled
    pub secret_key: Option<SecretStorage>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretStorage {
    pub kind: StorageType,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageType {
    Literal,
    FilePath,
}

impl Debug for SecretStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(),std::fmt::Error> {
        f.write_str(match &self.kind {
            StorageType::Literal => "Literal(***)",
            StorageType::FilePath => self.value.as_str(),
        })?;
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