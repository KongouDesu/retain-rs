use clap::ArgMatches;
use crate::config::Config;

mod upload;

pub fn backup(config: &Config, args: Option<&ArgMatches>) {
    match args.unwrap().value_of("action").unwrap() {
        "upload" => upload::start(config),
        "download" => unimplemented!(),
        "sync" => unimplemented!(),
        _ => panic!("Invalid action")
    }
}