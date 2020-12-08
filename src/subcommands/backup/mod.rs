use clap::ArgMatches;
use crate::config::Config;

mod upload;
mod download;

pub fn backup(config: &mut Config, args: Option<&ArgMatches>) {
    match args.unwrap().value_of("action").unwrap() {
        "upload" => upload::start(config),
        "download" => download::start(&config),
        "sync" => unimplemented!(),
        _ => panic!("Invalid action")
    }
}