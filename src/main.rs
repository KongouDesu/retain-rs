use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Duration;

use sodiumoxide;
use sodiumoxide::crypto::secretstream::{gen_key, Stream, Tag};
use sodiumoxide::crypto::secretstream::xchacha20poly1305;

mod colorutil;
use colorutil::printcoln;
use termcolor::Color;

use clap::{Arg, App, SubCommand, crate_version, ArgGroup};
use crate::config::Config;

mod config;

mod subcommands;


fn main() {
    let t_start = std::time::Instant::now();

    let args = App::new("retain-rs")
        .version(&crate_version!()[..])
        .author("Kongou <github.com/KongouDesu>")
        .about("Secure backup tool targeting Backblaze B2")
        .arg(Arg::with_name("location")
            .help("Location of config file")
            .short("c")
            .long("config")
            .default_value("retain.cfg"))
        .subcommand(SubCommand::with_name("config")
            .about("Configure this tool")
            .arg(Arg::with_name("appkeyid")
                .short("a")
                .long("app_key_id")
                .takes_value(true)
                .value_name("APP_KEY_ID"))
            .arg(Arg::with_name("appkey")
                .short("k")
                .long("app_key")
                .takes_value(true)
                .value_name("APP_KEY"))
            .arg(Arg::with_name("bucketname")
                .short("b")
                .long("bucket_name")
                .takes_value(true)
                .value_name("BUCKET_NAME"))
            .subcommand(SubCommand::with_name("secret")
                .about("Set how the encryption secret key should be handled")
                .arg(Arg::with_name("kind")
                    .help("How the secret key is stored. In the config file directly (string) or as a path to the key-file (path)")
                    .index(1)
                    .required(true)
                    .possible_values(&["string","path"])
                    .case_insensitive(true)
                    .value_name("KIND"))
                .arg(Arg::with_name("value")
                    .help("The secret key or the path to the file containing, depending on your choice for 'KIND'")
                    .index(2)
                    .required(true)
                    .value_name("KEY/PATH"))))


        .subcommand(SubCommand::with_name("status")
            .about("Display the status of the current configuration"))
        .subcommand(SubCommand::with_name("encryption")
            .about("Enable/disable encryption or encrypt/decrypt a file")
            .long_about("Enable/disable encryption or encrypt/decrypt a file\n\
            Uses the currently configured secret key")
            .arg(Arg::with_name("enable")
                .help("Enable or disable encryption")
                .short("t")
                .long("toggle")
                .possible_values(&["on","off"])
                .case_insensitive(true)
                .value_name("ON/OFF"))
            .arg(Arg::with_name("encrypt")
                .help("Encrypt the IN_FILE, creating an encrypted version in OUT_FILE")
                .short("e")
                .long("encrypt")
                .number_of_values(2)
                .takes_value(true)
                .value_names(&["IN_FILE","OUT_FILE"]))
            .arg(Arg::with_name("decrypt")
                .help("Decrypt the IN_FILE, placing the decrypted result in OUT_FILE")
                .short("d")
                .long("decrypt")
                .number_of_values(2)
                .takes_value(true)
                .value_names(&["IN_FILE","OUT_FILE"])))
        .subcommand(SubCommand::with_name("check")
            .about("Perform a check of the current configuration")
            .long_about("Perform a check of the current configuration\n\
                        This will verify that everything is configured\n\
                        Check that encryption works, if enabled\n\
                        Check if the authorization is valid\n\
                        Check if the bucket is accessible\n\
                        Check if the bucket has info about the backup\n\
                        Check if that info matches current settings"))
        .subcommand(SubCommand::with_name("init")
            .about("Enter interactive initialization mode")
            .long_about("Used to interactively set up the program\n\
            Walks through setting auth, choosing a bucket, etc.\n\
            Provides important information about encryption and how to choose what files gets uploaded"))
        .subcommand(SubCommand::with_name("backup")
            .about("Upload, download or synchronize with remote storage")
            .subcommand(SubCommand::with_name("upload"))
            .subcommand(SubCommand::with_name("download"))
            .subcommand(SubCommand::with_name("sync")))


        .get_matches();


    // Load config file
    let cfg_location = args.value_of("location").unwrap();
    let mut config = Config::from_file(cfg_location);
    println!("{:?}", config);

    match args.subcommand() {
        ("config", config_args) => subcommands::configure(&mut config, config_args),
        ("status", status_args) => subcommands::status(&config),
        ("encryption", encrypt_args) => unimplemented!(),
        ("check", _check_args) => unimplemented!(),
        _ => {
            println!("{}",args.usage());
        }
    };

    // Save config
    config.save_to(cfg_location).unwrap();


    printcoln(Color::Green, format!("[{:.3}] Init SodiumOxide", t_start.elapsed().as_secs_f32()));
    match sodiumoxide::init() {
        Ok(()) => (),
        Err(()) => {
            printcoln(Color::Red, format!("[{:.3}] SodiumOxide init failed!", t_start.elapsed().as_secs_f32()));
            panic!("SodiumOxide init failure");
        }
    }
    printcoln(Color::Green, format!("[{:.3}] Init OK", t_start.elapsed().as_secs_f32()));

}
