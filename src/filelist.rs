//! Logic for the "backup list" functionality
//!
//! The backup list file defines which files get included and excluding when performing backups
//! The file consists of a list of rules
//! The default behavior is to not upload any files
//! Every rule adds files to upload, optionally filtering some out
//!
//! Rule structure:
//! A rule starts with a path to a file or directory
//! If it's a file, that file will be uploaded and no filtering can be applied
//! If it's a directory, it can be followed by any number of filtering rules
//! Each filter rule is a regular expression. Anything that matches this regex is excluded
//! Filter rules start with a '-' followed by the expression
//!
//! Example:
//! ```
//! /home/user/
//! - target/
//! - \.txt$
//! /etc/foo/config.cfg
//! ```
//! This will upload every file is `user`'s home directory, excluding anything inside a `target/` directory and any `.txt` files
//!
//! Note that by default it will match anywhere in the sub-path \
//! Consider a file with path `/home/user/documents/target/books/book.pdf` \
//! It is included by the `/home/user/` rule. The filters are then applied only on the sub-path, i.e. `documents/target/books/book.pdf` \
//! Since this matches `- target/`, it will not be uploaded

use std::path::Path;
use regex::{Regex,RegexSet};
use walkdir::WalkDir;
use std::fs::FileType;

/// Verifies the structure of the backup list is correct without collecting files
/// Returns OK or an Err with where in the file it encountered an error
pub fn verify_structure<T: AsRef<Path>>(file: T) -> Result<(),String> {
    let text = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(err) => {
            format!("Failed to open backup list {:?}", err)
        }
    };

    let mut lines = text.lines();
    let mut dir = match lines.next() {
        Some(s) => s.trim(),
        None => return Err("Backup list contains no entries".to_owned()),
    };
    if dir.starts_with("-") {
        return Err("Backup list started with a filter, not a path".to_string());
    }
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('-') {
            if Regex::new(line).is_err() {
                return Err(format!("Invalid RegEx - {}", line))
            }
        } else {
            if !std::path::Path::new(line).exists() {
                return Err(format!("File/Directory not found - {}", line))
            }
        }
    }

    Ok(())
}

/// Applies each rule in the backup list, returning a Vec with each file that is to be uploaded
pub fn build_file_list<T: AsRef<Path>>(file: T) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    let text = std::fs::read_to_string(file).unwrap();

    let mut regex_str = Vec::new();
    let mut lines = text.lines();
    let mut dir = lines.next().unwrap().trim();
    if dir.starts_with("-") {
        panic!("Backup list started with a filter, not a path")
    }

    // Check for new filters until we encounter a path
    // When we encounter a path, collect files for the current using discovered rules
    // Then, reset rules and repeat
    // Note: we chain an empty string to make sure it adds the last entry
    for line in lines.chain(vec![""]) {
        let line = line.trim();
        if line.starts_with("-") {
            regex_str.push(line[1..].trim());
        } else {
            // New path encountered
            // Construct RegEx set, recursively walk directory
            let reg_set = RegexSet::new(&regex_str).unwrap();

            regex_str.clear();
            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                let name = match entry.path().to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if !reg_set.is_match(name) && entry.file_type().is_file() {
                    files.push(name.to_string());
                }
            }
            dir = line;
        }
    }

    files
}
