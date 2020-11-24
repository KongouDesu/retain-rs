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
    // Original name, modified timestamp, masked name
    files: Vec<FileEntry>,
    #[serde(skip)]
    mask: bool, // If true, mask names, if false, translate to B2 friendly paths
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

    // Get the mask for an existing entry or generate a new one if it doesn't exist
    pub fn get_or_generate_mask<T: AsRef<str>>(&mut self, path: T, timestamp: u64) -> String {
        match self.files.binary_search_by(|e| (e.path[..]).cmp(path.as_ref())) {
            Ok(n) => self.files[n].mask.to_string(),
            Err(n) => {
                let rng = thread_rng();
                self.files.insert(n, FileEntry {
                    path: path.as_ref().to_string(),
                    timestamp,
                    mask: rng.sample_iter(Alphanumeric).take(MASK_SIZE).collect(),
                });
                self.files[n].mask.to_string()
            },
        }
    }

    pub fn get_timestamp_for_path<T: AsRef<str>>(&mut self, path: T) -> Option<u64> {
        match self.files.binary_search_by(|e| (e.path[..].cmp(path.as_ref()))) {
            Ok(n) => Some(self.files[n].timestamp),
            Err(_) => None,
        }
    }

    // TODO Function to get modified time and path from mask
    // TODO Function to remove entry

    // Under Unix, all paths are naturally prefix with '/' (the root)
    // B2 will not emulate folders if we start the path with a slash,
    // so we strip it here to make it behave correctly
    // let name_in_b2 = if cfg!(windows) {
    // &path_str
    // } else {
    // &path_str[1..]
    // };
}

#[cfg(test)]
mod tests {
    use crate::manifest::{FileManifest, MASK_SIZE};

    #[test]
    fn test_generate() {
        let mut fm = FileManifest {
            files: vec![],
            mask: false
        };
        let mask = fm.get_or_generate_mask("file.txt", 4908);
        println!("{}", mask);
        assert_eq!(mask.len(),MASK_SIZE);
        let mask2 = fm.get_or_generate_mask("file.txt", 4908);
        assert_eq!(mask, mask2);
    }
}