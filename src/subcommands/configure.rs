use crate::config::{Config};
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

    if let Some(s) = args.value_of("filelist") {
        config.backup_list = Some(s.to_string());
        println!("Set File List Path: {}", s);
        if !std::path::Path::new(s).is_file() {
            printcoln(Color::Red, "Warning: file is either missing or inaccessible")
        }
    }

    if let Some(s) = args.value_of("secret") {
        config.secret_key = Some(s.to_string());
        println!("Set Keyfile Path: {}", s);
        if !std::path::Path::new(s).is_file() {
            printcoln(Color::Red, "Warning: keyfile is either missing or inaccessible")
        }
    }

}