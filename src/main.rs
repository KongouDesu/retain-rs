mod colorutil;

use clap::{Arg, App, SubCommand, crate_version};
use crate::config::Config;

mod config;
mod subcommands;
mod filelist;
mod encryption;
mod manifest;


fn main() {
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
            .arg(Arg::with_name("filelist")
                .short("l")
                .long("list")
                .takes_value(true)
                .value_name("FILE_LIST"))
            .arg(Arg::with_name("secret")
                .help("Path to keyfile")
                .short("s")
                .long("secret")
                .takes_value(true)
                .value_name("SECRET_FILE")))


        .subcommand(SubCommand::with_name("status")
            .about("Display the status of the current configuration"))
        .subcommand(SubCommand::with_name("encryption")
            .about("Enable/disable encryption or encrypt/decrypt a file")
            .long_about("Enable/disable encryption, encrypt/decrypt a file or generate a new key\n\
            Uses the currently configured secret key")
            .arg(Arg::with_name("enable")
                .help("Enable or disable encryption")
                .short("t")
                .long("toggle")
                .possible_values(&["on","off"])
                .case_insensitive(true)
                .value_name("ON/OFF"))
            .arg(Arg::with_name("keygen")
                .help("Generate a new secret key and set it as active key")
                .short("g")
                .long("genkey")
                .takes_value(true)
                .value_name("FILE"))
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
            .about("Checks the config and attempts to resolve de-synchronization with remote")
            .long_about("Ensures the configuration is correct\n
            Attempts to resolve de-synchronization\n\
            Local and remote can become desynchronized due to interruptions or errors\n\
            This can result in wasted space on remote and/or some files not being backed up\n\
            If a remote file cannot be found in the local manifest, it is deleted\n\
            If a local file cannot find it's corresponding remote entry, it is removed from the local manifest\n\
            Note that this means you may need to run 'backup upload' afterwards to ensure all files are uploaded"))
        .subcommand(SubCommand::with_name("init")
            .about("Enter interactive initialization mode")
            .long_about("Used to interactively set up the program\n\
            Walks through setting auth, choosing a bucket, etc.\n\
            Provides important information about encryption and how to choose what files gets uploaded"))
        .subcommand(SubCommand::with_name("backup")
            .about("Upload, download or synchronize with remote storage")
            .arg(Arg::with_name("action")
                .help("Type of backup action to take, upload, download or synchronize")
                .required(true)
                .possible_values(&["upload","download","sync"])
                .case_insensitive(true)
                .min_values(1)
                .max_values(1)
                .index(1)))


        .get_matches();


    // Load config file
    let cfg_location = args.value_of("location").unwrap();
    let mut config = Config::from_file(cfg_location);
    //println!("{:?}", config);

    match args.subcommand() {
        ("config", config_args) => {
            subcommands::configure(&mut config, config_args);
            // Save config
            config.save_to(cfg_location).unwrap();
        },
        ("status", status_args) => subcommands::status(&config),
        ("backup", backup_args) => subcommands::backup::backup(&mut config, backup_args),
        ("encryption", encrypt_args) => subcommands::encrypt::encrypt(&mut config, encrypt_args),
        ("check", _check_args) => unimplemented!(),
        _ => {
            println!("{}",args.usage());
        }
    };




}
