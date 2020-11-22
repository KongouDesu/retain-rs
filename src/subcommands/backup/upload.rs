use crate::config::Config;
use crate::filelist;
use crate::colorutil::printcoln;
use termcolor::Color;
use scoped_pool::Pool;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use raze::api::{BucketResult, ListBucketParams};
use raze::Error;

pub fn start(config: &Config) {
    let t_start = std::time::Instant::now();
    // If this succeeds, all values are set and we can unwrap them
    match &config.is_configured() {
        Ok(_) => (),
        Err(err) => {
            printcoln(Color::Red, format!("Invalid config ({})", err));
            return;
        }
    }

    // Ensures list is found and structure is valid
    match filelist::verify_structure(config.backup_list.as_ref().unwrap()) {
        Ok(_) => (),
        Err(e) => {
            printcoln(Color::Red, format!("{}", e));
        }
    }

    match config.encrypt.unwrap() {
        true => {
            printcoln(Color::Green, "Encryption is enabled");
            // TODO: Verify encryption works on this platform(?)
            printcoln(Color::Green, format!("[{:.3}] Init OK", t_start.elapsed().as_secs_f32()));
        }
        false => {
            printcoln(Color::Yellow, "Encryption is disabled")
        }
    }

    printcoln(Color::Green, format!("[{:.3}] Building list of files to upload...", t_start.elapsed().as_secs_f32()));
    let files = filelist::build_file_list(config.backup_list.as_ref().unwrap());
    printcoln(Color::Green, format!("[{:.3}] Complete ({} files)", t_start.elapsed().as_secs_f32(), files.len()));

    let files = Arc::new(Mutex::new(files));
    let client = reqwest::blocking::Client::builder().timeout(None).build().unwrap();

    printcoln(Color::Green, format!("[{:.3}] Authenticating...", t_start.elapsed().as_secs_f32()));

    let keystring = format!("{}:{}", config.app_key_id.as_ref().unwrap(), config.app_key.as_ref().unwrap());
    let auth = match raze::api::b2_authorize_account(&client,keystring) {
        Ok(a) => a,
        Err(_e) => {
            printcoln(Color::Red, format!("[{:.3}] Authentication failure", t_start.elapsed().as_secs_f32()));
            return;
        },
    };
    printcoln(Color::Green, format!("[{:.3}] Success", t_start.elapsed().as_secs_f32()));
    printcoln(Color::Green, format!("[{:.3}] Resolving bucket name", t_start.elapsed().as_secs_f32()));

    let params = ListBucketParams {
        bucket_id: None,
        bucket_name: Some(config.bucket_name.as_ref().unwrap().to_string()),
        bucket_types: None
    };
    let buckets = match raze::api::b2_list_buckets(&client, &auth, params) {
        Ok(buckets) => buckets,
        Err(err) => {
            printcoln(Color::Red, format!("[{:.3}] Failed to retrieve bucket list", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] Reason: {:?}", t_start.elapsed().as_secs_f32(), err));
            return;
        }
    };

    let bucket_name = config.bucket_name.as_ref().unwrap();
    let bucket_id = match buckets.iter().find(|b| &b.bucket_name == bucket_name) {
        Some(bid) => &bid.bucket_id,
        None => {
            printcoln(Color::Red, format!("[{:.3}] No bucket with the name '{}'", t_start.elapsed().as_secs_f32(), bucket_name));
            return;
        }
    };
    printcoln(Color::Green, format!("[{:.3}] {} -> {}", t_start.elapsed().as_secs_f32(), bucket_name, bucket_id));

    printcoln(Color::Green, format!("[{:.3}] Beginning upload", t_start.elapsed().as_secs_f32()));
    let pool = Pool::new(8); // Pool size = num threads = concurrent uploads
    pool.scoped(|scope| {
        // Spawn 1 task per worker
        for i in 0..pool.workers() {
            let files = files.clone();
            let client = &client;
            let auth = &auth;
            scope.execute(move || {
                let upauth = raze::api::b2_get_upload_url(&client, &auth, bucket_id).unwrap();
                loop {
                    // Try to get a file to upload
                    let p = {
                        files.lock().unwrap().pop()
                    };
                    let path = match p {
                        Some(p) => p,
                        None => {
                            // List is empty, nothing more to upload
                            break;
                        }
                    };
                    let path_str = path.replace("\\", "/");

                    // TODO: we only need to do this if encryption is disabled
                    // Under Unix, all paths are naturally prefix with '/' (the root)
                    // B2 will not emulate folders if we start the path with a slash,
                    // so we strip it here to make it behave correctly
                    let name_in_b2 = if cfg!(windows) {
                        &path_str
                    } else {
                        &path_str[1..]
                    };

                    // TODO Check if the file is already backed up
                    // TODO If it is, compare modified time to see if we should upload it
                    /*
                    // Compare modified time
                    let do_upload: bool;
                    let metadata = match std::fs::metadata(&path) {
                        Ok(m) => m,
                        Err(e) => {
                            println!("Failed to get metadata, skipping file ({:?})", e);
                            continue;
                        }
                    };
                    let modified_time = match metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH) {
                        Ok(v) => v.as_secs() * 1000, // Convert seconds to milliseconds
                        Err(_e) => 0u64
                    };
                    let filesize = metadata.len(); // Used later as well

                    match sfl.binary_search(&sf) {
                        Ok(v) => { // A file with the same path+name exists
                            // Check if the local file was modified since it was last uploaded
                            if modified_time > sfl[v].upload_timestamp {
                                do_upload = true;
                            } else {
                                do_upload = false;
                            }
                        },
                        Err(_e) => { // No matching path+name exists
                            do_upload = true;
                        }
                    }
                    if !do_upload {
                        //println!("Skipping {:?}", path_str);
                        continue;
                    }
                     */
                    println!("Uploading {:?}", path_str);

                    // Try uploading up to 5 times
                    for attempts in 0..5 {
                        let file = match std::fs::File::open(&path) {
                            Ok(f) => f,
                            Err(e) => {
                                println!("Failed to open file {:?} ({:?}) - It will not be uploaded", path, e);
                                break;
                            }
                        };

                        // TODO if encryption is on, the filesize will be larger
                        /*
                        let params = raze::api::FileParameters {
                            file_path: name_in_b2,
                            file_size: filesize,
                            content_type: None, // auto
                            content_sha1: Sha1Variant::HexAtEnd,
                            last_modified_millis: modified_time
                        };
                         */

                        // If bandwidth == 0, do not throttle
                        // TODO We need to wrap this in the encrypting `Read`er
                        /*
                        let result = if bandwidth > 0 {
                            let file = raze::util::ReadThrottled::wrap(
                                raze::util::ReadHashAtEnd::wrap(file), bandwidth);
                            raze::api::b2_upload_file(&client, &upauth, file, params)
                        } else {
                            let file = raze::util::ReadHashAtEnd::wrap(file);
                            raze::api::b2_upload_file(&client, &upauth, file, params)
                        };
                         */

                        /*
                        match result {
                            Ok(_) => break,
                            Err(e) => {
                                println!("Upload failed: {:?}", e);
                                match e {
                                    raze::Error::ReqwestError(e) => { println!("Reason: {:?}", e); },
                                    raze::Error::IOError(e) => { println!("Reason: {:?}", e); },
                                    raze::Error::SerdeError(e) => { println!("Reason: {:?}", e); },
                                    raze::Error::B2Error(e) => {
                                        // TODO: consider adding re-auth here
                                        // Both 'auth' and 'upauth' can expire
                                        println!("Reason: {:?}", e);
                                    },
                                }

                                if attempts == 4 {
                                    println!("Failed to upload {:?} after 5 attempts", path);
                                } else {
                                    // Sleep and retry
                                    std::thread::sleep(Duration::from_millis(5000));
                                    continue;
                                }
                            }
                        }

                         */
                    }
                }
            });
        }
    });
}