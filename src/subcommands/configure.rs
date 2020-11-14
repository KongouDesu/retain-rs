use crate::config::{Config, SecretStorage, StorageType};
use clap::ArgMatches;
use std::str::FromStr;
use crate::colorutil::printcoln;
use termcolor::Color;

/// Updates the configuration according to the provided args
pub fn configure(config: &mut Config, args: Option<&ArgMatches>) {
    if args.is_none() {
        println!("Nothing to configure");
        return;
    }
    let args = args.unwrap();

    if let Some(s) = args.value_of("appkeyid") {
        config.app_key_id = Some(s.to_string());
        println!("Set App Key ID: {}", s);
    }

    if let Some(s) = args.value_of("appkey") {
        config.app_key = Some(s.to_string());
        println!("Set App Key: {}", s);
    }

    if let Some(s) = args.value_of("bucketname") {
        config.bucket_name = Some(s.to_string());
        println!("Set Bucket Name: {}", s);
    }

    match args.subcommand() {
        ("secret", secret_args) => {
            // Safe to unwrap: Clap verifies args are present before we reach this
            let secret_args = secret_args.unwrap();
            let kind = match secret_args.value_of("kind").unwrap().to_lowercase().as_str() {
                "string" => StorageType::Literal,
                "path" => StorageType::FilePath,
                s => panic!(format!("Unexpected value {:?} for secret kind", s)),
            };
            let value = secret_args.value_of("value").unwrap().to_string();
            config.secret_key = Some(SecretStorage {
                kind,
                value,
            });
        }
        _ => ()
    }
}