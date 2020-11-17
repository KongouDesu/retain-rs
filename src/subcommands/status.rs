use crate::config::Config;
use crate::colorutil::{printcoln,printcol};
use termcolor::Color;

/// Print out information about the state of the config
pub fn status(config: &Config) {
    print!("App Key ID: \t");
    match &config.app_key_id {
        Some(k) => printcoln(Color::Green, k),
        None => printcoln(Color::Red, "Unset"),
    };

    print!("App Key: \t");
    match &config.app_key {
        Some(k) => printcoln(Color::Green, k),
        None => printcoln(Color::Red, "Unset"),
    };

    print!("Bucket Name: \t");
    match &config.bucket_name {
        Some(k) => printcoln(Color::Green, k),
        None => printcoln(Color::Red, "Unset"),
    };

    print!("Encryption: \t");
    match &config.encrypt {
        Some(enc) => printcoln(Color::Green, format!("Configured: {}",if *enc {"on"} else {"off"})),
        None => printcoln(Color::Red, "Unset"),
    };

    print!("Secret Key: \t");
    if config.encrypt.is_some() && !config.encrypt.unwrap() {
        printcoln(Color::Yellow, "Encryption Disabled")
    } else {
        match &config.secret_key {
            Some(s) => {
                if std::path::Path::new(&s).is_file() {
                    printcoln(Color::Green, format!("{}", s))
                } else {
                    printcoln(Color::Red, format!("File not found or inaccessible ({})", s))
                }
            }
            None => {
                printcoln(Color::Red, "No secret keyfile set");
            }
        }
    }


}
