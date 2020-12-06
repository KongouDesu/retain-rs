/// This module provides the FileManifest struct, for keeping track of files
///
/// When encryption is on, file names are masked when uploaded
/// This file provides mappings from local names <-> masked names, as well as modified times
/// This also means all state is local. We do not need to query BackBlaze for info before up/downloading
/// This file is encrypted and backed up, s.t. file names can be recovered if the file is lost but the key is not
///
/// Note that valid B2 names are:
/// UTF-8 String, max 1024 bytes
/// Only codes >= 32, except 127 (DEL)
///
/// Note that if encryption is disabled, the "masked name" will instead be the input path, but
/// formatted as an absolute path, using '/' separators and works with BackBlaze web view

use serde::{Serialize, Deserialize};
use std::error::Error;
use std::cmp::Ordering;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::borrow::Cow;

// Amount of Alphanumeric characters used to make a masked name
const MASK_SIZE: usize = 64;

#[derive(Serialize,Deserialize,Debug)]
pub struct FileManifest {
    // If true, mask names, if false, translate to B2 friendly paths
    mask: bool,
    // Original name, modified timestamp, masked name
    files: Vec<FileEntry>,
}

#[derive(Serialize,Deserialize,Debug)]
struct FileEntry {
    path: String,
    timestamp: u64,
    mask: String,
}


impl FileManifest {
    pub fn from_file<T: AsRef<str>>(path: T) -> Result<Self,Box<dyn Error>> {
        Ok(serde_json::from_slice::<Self>(&std::fs::read(path.as_ref())?)?)
    }

    pub fn to_file<T: AsRef<str>>(&self, path: T) -> Result<(),Box<dyn Error>> {
        Ok(std::fs::write(path.as_ref(),serde_json::to_vec(self)?)?)
    }

    /// Returns the mask used for the given path
    /// If no entry exists, a new mask is generated
    /// If we aren't encrypting (self.mask is false), we use a B2-friendly name instead
    pub fn get_mask<T: AsRef<str>>(&mut self, path: T, timestamp: u64) -> (u64,String) {
        match self.files.binary_search_by(|e| (e.path[..]).cmp(path.as_ref())) {
            Ok(n) => (self.files[n].timestamp,self.files[n].mask.to_string()),
            Err(n) => {
                let rng = thread_rng();
                let new_mask = match self.mask {
                    true => rng.sample_iter(Alphanumeric).take(MASK_SIZE).collect(),
                    false => {
                        // On Unix-whatever, everything is prefixed with the '/' root
                        // B2's web interface will not emulate folders unless we strip it
                        // Note that we _will_ have to add it back when downloading files
                        if cfg!(windows) {
                            path.as_ref().to_string()
                        } else {
                            path.as_ref()[1..].to_string()
                        }
                    }
                };
                self.files.insert(n, FileEntry {
                    path: path.as_ref().to_string(),
                    timestamp,
                    mask: new_mask,
                });
                (timestamp,self.files[n].mask.to_string())
            },
        }
    }

    // If an entry with the supplied path exists, update its timestamp to the supplied value
    pub fn update_timestamp<T: AsRef<str>>(&mut self, path: T, timestamp: u64) {
        match self.files.binary_search_by(|e| (e.path[..]).cmp(path.as_ref())) {
            Ok(n) => self.files[n].timestamp = timestamp,
            Err(_) => (),
        };
    }

    // Returns (timestamp,mask) if an entry with the given path exists, otherwise None
    pub fn get_from_path<T: AsRef<str>>(&mut self, path: T) -> Option<(u64,String)> {
        match self.files.binary_search_by(|e| (e.path[..].cmp(path.as_ref()))) {
            Ok(n) => Some((self.files[n].timestamp,self.files[n].mask.clone())),
            Err(_) => None,
        }
    }

    // Returns (timestamp,path) if an entry with the given mask exists, otherwise None
    #[allow(dead_code)]
    pub fn get_from_mask<T: AsRef<str>>(&mut self, mask: T) -> Option<(u64,String)> {
        let result = self.files.iter().find(|e| &e.mask[..] == mask.as_ref());
        match result {
            Some(r) => Some((r.timestamp,r.path.to_string())),
            None => None,
        }
    }

    // Remove the entry matching the given path, if it exists
    #[allow(dead_code)]
    pub fn remove_path<T: AsRef<str>>(&mut self, path: T) {
        let idx = self.files.binary_search_by(|e| (e.path[..]).cmp(path.as_ref()));
        match idx {
            Ok(n) => self.files.remove(n),
            Err(_) => return,
        };
    }

    // Remove the entry matching the given mask, if it exists
    #[allow(dead_code)]
    pub fn remove_mask<T: AsRef<str>>(&mut self, mask: T) {
        let idx = self.files.binary_search_by(|e| (e.mask[..]).cmp(mask.as_ref()));
        match idx {
            Ok(n) => self.files.remove(n),
            Err(_) => return,
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::manifest::{FileManifest, MASK_SIZE};

    #[test]
    fn test_masking() {
        let mut fm = FileManifest {
            files: vec![],
            mask: true
        };
        let mask = fm.get_mask("file.txt", 4908);
        assert_eq!(mask.1.len(),MASK_SIZE);
        let mask2 = fm.get_mask("file.txt", 4908);
        assert_eq!(mask, mask2);

        let path = fm.get_from_mask(&mask.1).unwrap();
        assert_eq!(path.1,"file.txt".to_string());
        let mask3 = fm.get_from_path(&path.1).unwrap();
        assert_eq!(mask.1,mask3.1);

        fm.remove_path("file.txt");
        assert_eq!(true,fm.get_from_path("file.txt").is_none());
        let mask4 = fm.get_mask("file2.txt", 3464);
        assert_ne!(mask4.0,mask.0);
        assert_ne!(mask4.1,mask.1);

        fm.remove_mask(&mask4.1);
        assert_eq!(true,fm.get_from_mask(mask4.1).is_none());
    }

    #[test]
    fn test_nomask() {
        let mut fm = FileManifest {
            files: vec![],
            mask: false
        };
        let mask = fm.get_mask("file.txt", 4908);
        if cfg!(windows) {
            assert_eq!(mask.1.len(), "file.txt".len());
            assert_eq!("file.txt", mask.1);
        } else {
            assert_eq!(mask.1.len(), "file.txt".len()-1);
            assert_eq!("ile.txt", mask.1);
        }
    }
}