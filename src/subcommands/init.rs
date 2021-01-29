use crate::config::Config;
use crate::colorutil::{printcoln, printcol};
use termcolor::Color;
use std::io::{stdin, Read, Write, BufRead};
use raze::api::ListBucketParams;
use rand::{thread_rng, Rng};
use crate::manifest::FileManifest;
use std::path::Path;
use std::process::abort;

pub fn init(config: &mut Config) {
    printcoln(Color::Yellow,"Welcome to the retain-rs setup util");
    printcoln(Color::Yellow,format!("Initializing config as {}",config.location));
    println!();

    if Path::new("retain-rs-key").exists() {
        printcoln(Color::Red, "Error: an old encryption key exists at 'retain-rs-key'");
        printcoln(Color::Red, "Manually back up the key before re-running init");
        printcoln(Color::Red, "Notice: 'init' is not intended to re-configure the program");
        printcoln(Color::Red, "If you want to change settings, use 'config' instead!");
        panic!("retain-rs-key already exists! Aborting to avoid potentially overwriting secret key!");
    }
    if Path::new("manifest.json").exists() {
        printcoln(Color::Red, "Warning: an old file manifest exists at 'manifest.json'");
        printcoln(Color::Red, "Continuing will erase the current manifest.json file");
        printcoln(Color::Red, "This will cause desynchronization between local and remote");
        printcoln(Color::Red, "If encryption is on, file names for files in remote will be lost");
        printcoln(Color::Red, "Notice: 'init' is not intended to re-configure the program");
        printcoln(Color::Red, "If you want to change settings, use 'config' instead!");
    }

    println!();
    printcoln(Color::Yellow, "First we need to set up authentication with the B2 API");

    let client = reqwest::blocking::Client::builder().timeout(None).build().unwrap();
    let mut auth = None;
    loop {
        printcol(Color::White,"App Key ID: ");
        let appkeyid = stdin().lock().lines().next().unwrap().unwrap();
        printcol(Color::White,"App Key: ");
        let appkey = stdin().lock().lines().next().unwrap().unwrap();
        printcoln(Color::Yellow, "Trying to authenticate...");

        let keystring = format!("{}:{}", appkeyid, appkey);
        match raze::api::b2_authorize_account(&client,keystring) {
            Ok(a) => {
                auth = Some(a);
                config.app_key_id = Some(appkeyid);
                config.app_key = Some(appkey);
            },
            Err(_e) => {
                printcoln(Color::Red, format!("Authentication failure"));
                continue;
            },
        };
        break;
    }
    let auth = auth.unwrap();
    printcoln(Color::Green, "Success");

    printcoln(Color::Yellow, "Attempting to retrieve list of buckets");
    let params = ListBucketParams {
        bucket_id: None,
        bucket_name: None,
        bucket_types: None
    };

    let buckets = match raze::api::b2_list_buckets(&client, &auth, params) {
        Ok(list) => {
            printcoln(Color::Yellow, "Available buckets:");
            for bucket in &list {
                printcoln(Color::White, &bucket.bucket_name);
            }
            list
        }
        Err(_) => {
            printcoln(Color::Yellow, "Failed to get list of buckets");
            printcoln(Color::Yellow, "This is likely because the supplied auth is restricted to a specific bucket");
            printcoln(Color::Yellow, "If that is the case, you can ignore this error");
            vec![]
        },
    };
    printcoln(Color::Yellow, "Select which bucket to use");
    loop {
        printcol(Color::White, "Bucket name: ");
        let bucket = stdin().lock().lines().next().unwrap().unwrap();
        // Check if it's in the list of buckets we retrieved
        // If we got no buckets, make a new request to check the name is valid
        if buckets.len() == 0 {
            printcoln(Color::Yellow, "Verifying bucket...");
            // If the auth is restricted to one specific bucket, we can make a request to check
            // that the entered bucket name is valid
            // We ask for one specific bucket: the one the user entered
            let params = ListBucketParams {
                bucket_id: None,
                bucket_name: Some(bucket.to_string()),
                bucket_types: None
            };
            // We either get 1 bucket (the one we asked for) or an error
            // If we get 1, it is valid
            if raze::api::b2_list_buckets(&client, &auth, params).unwrap_or(vec![]).len() == 1 {
                config.bucket_name = Some(bucket);
                printcoln(Color::Green, "OK");
                break;
            } else {
                printcoln(Color::Red, format!("'{}' does not appear to be a valid bucket", bucket));
                printcoln(Color::Red, "Ensure you spelled it correctly and the auth has permission access it");
            }
        } else { // If we got a list, check what was entered is an entry in that list
            if buckets.iter().find(|e| e.bucket_name == bucket).is_some() {
                config.bucket_name = Some(bucket);
                break;
            } else {
                printcoln(Color::Red, format!("Could not find {} in list of available buckets", bucket));
            }
        }
    }

    printcoln(Color::Yellow, "Enter where to store the backup-list file");
    printcoln(Color::Yellow, "This is where you tell what files to include and exclude");
    printcol(Color::White, "Name: ");
    let backuplist = stdin().lock().lines().next().unwrap().unwrap();
    printcoln(Color::Yellow, format!("Backup file list location: {}", backuplist));
    if !Path::new(&backuplist).exists() {
        std::fs::write(&backuplist, "--- Backup definitions go here, refer to docs for more info ---").unwrap_or_else(|_|
        printcoln(Color::Yellow, "Failed to create backup-list file, please create it yourself"));
    }
    config.backup_list = Some(backuplist);



    printcoln(Color::Yellow, "-----");
    printcoln(Color::Yellow, "Enable encryption?");
    printcoln(Color::Yellow, "Note that once enabled, you cannot disable it without re-uploading all files!");
    printcoln(Color::Yellow, "If enabled, a file 'retain-rs-key' will be created");
    printcoln(Color::Yellow, "This is a SECRET key necessary to encrypt/decrypt your data");
    printcoln(Color::Yellow, "You MUST store this file somewhere safe -- If lost, your data cannot be decrypted");
    loop {
        printcol(Color::White, "Enable encryption? (y/n): ");
        let encrypt = stdin().lock().lines().next().unwrap().unwrap();
        match encrypt.as_ref() {
            "y" => {
                printcoln(Color::Green, "Encryption is ON");
                FileManifest {
                    mask: true,
                    remote_id: "not_yet_set".to_string(),
                    files: vec![]
                }.to_file("manifest.json").unwrap();
                config.encrypt = Some(true);
                config.secret_key = Some("retain-rs-key".to_string());
                // Generate key
                let mut rng = thread_rng();
                let mut key_bytes = [0u8; 32];
                rng.try_fill(&mut key_bytes).expect("Failed to generate key");
                std::fs::write("retain-rs-key", key_bytes).expect("Failed to save key");
                break;
            },
            "n" => {
                printcoln(Color::Yellow, "Encryption is OFF");
                config.encrypt = Some(false);
                FileManifest {
                    mask: false,
                    remote_id: "not_yet_set".to_string(),
                    files: vec![]
                }.to_file("manifest.json").unwrap();
                break;
            }
            _ => {
                continue;
            }
        };
    }

    config.save();
    printcoln(Color::Green, "Init completed!");
    printcoln(Color::Green, "Populate the backup list file and start uploading");
}