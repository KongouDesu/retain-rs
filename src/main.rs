mod colorutil;

use clap::{Arg, App, SubCommand, crate_version, AppSettings};
use crate::config::Config;

mod config;
mod subcommands;
mod filelist;
mod encryption;
mod manifest;


fn main() {
    let mut app = App::new("retain-rs")
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

        .subcommand(SubCommand::with_name("clean")
            .about("Fix de-sync and clean up unused files")
            .long_about("Resolved de-synchronization and removes unused files\n\
            Local and remote can become de-synchronized due to interruptions or errors\n\
            If this happens, some files may not be backed up and/or we may be wasting space\n\
            Files no longer found on the local system are also cleaned up\n\
            Note that this never removes any local files\n\
            It is recommended to run 'backup upload' afterwards to ensure everything is synced")
            .arg(Arg::with_name("mode")
                .help("Whether to hide (soft-delete) or hard-delete unused files")
                .takes_value(true)
                .case_insensitive(true)
                .required(true)
                .possible_values(&["hide","delete"]))
            .arg(Arg::with_name("fast")
                .help("Use manifest to determine what files exist instead of querying B2 (which is slow)\n\
                Note that this will miss some files if manifest and remote are de-synchronized")
                .case_insensitive(true)
                .long("fast"))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force cleanup, using local manifest.json without checking remote one first")))

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
                .index(1)));

    let args = app.get_matches();

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
        ("status", _status_args) => subcommands::status(&config),
        ("backup", backup_args) => subcommands::backup::backup(&mut config, backup_args),
        ("encryption", encrypt_args) => subcommands::encrypt::encrypt(&mut config, encrypt_args),
        ("clean", clean_args) => subcommands::clean::clean_using_clap(&mut config, clean_args),
        ("init", _) => subcommands::init::init(&mut config),
        _ => {
            println!("{}", args.usage());
            println!("\tUse -h for full help");
        }
    };




}
