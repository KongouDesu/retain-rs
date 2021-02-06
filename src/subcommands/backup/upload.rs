use crate::config::Config;
use crate::filelist;
use crate::colorutil::printcoln;
use termcolor::Color;
use scoped_pool::Pool;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use raze::api::{BucketResult, ListBucketParams, Sha1Variant};
use raze::Error;
use crate::encryption::{get_encrypted_size, get_nonces_required};
use crate::encryption::reader::EncryptingReader;
use chacha20poly1305::Key;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use ctrlc;
use std::sync::mpsc;
use std::process::abort;

// Start backing up files
// This will:
// 1. Check that everything in the config is set
// 2. Build the list of files defined in the backup-list
// 3. Authenticate with the B2 API
// 4. Upload new and changed files
pub fn start(config: &mut Config) {
    let t_start = std::time::Instant::now();
    // If this succeeds, all values are set and we can unwrap them
    match config.is_configured() {
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
            printcoln(Color::Red, format!("Backup list is invalid: {}", e));
            return;
        }
    }

    let mut key = None;
    match config.encrypt.unwrap() {
        true => {
            printcoln(Color::Green, "Encryption is enabled");
            // TODO: Verify encryption works on this platform(?)
            match std::fs::read(config.secret_key.as_ref().unwrap()) {
                Ok(bytes) => {
                    key = Some(Key::clone_from_slice(&bytes));
                }
                Err(err) => {
                    printcoln(Color::Red, format!("[{:.3}] Failed to open key-file {:?}", t_start.elapsed().as_secs_f32(), err));
                    return;
                }
            }
            printcoln(Color::Green, format!("[{:.3}] Init OK", t_start.elapsed().as_secs_f32()));
        }
        false => {
            printcoln(Color::Yellow, "Encryption is disabled");
        }
    }

    printcoln(Color::Green, format!("[{:.3}] Loading local file manifest", t_start.elapsed().as_secs_f32()));
    let mut manifest = match crate::manifest::FileManifest::from_file("manifest.json") {
        Ok(fm) => fm,
        Err(err) => {
            printcoln(Color::Red, format!("[{:.3}] Failed to load file manifest ({})", t_start.elapsed().as_secs_f32(), err));
            printcoln(Color::Yellow, format!("[{:.3}] If it is missing due to the program being set up without using the init command:", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Yellow, format!("[{:.3}] * Run init to generate a new one, starting tracking from scratch", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Yellow, format!("[{:.3}] * Or ensure your previous manifest can be found", t_start.elapsed().as_secs_f32()));
            return;
        }
    };
    let manifest_mutex = Mutex::new(&mut manifest);
    printcoln(Color::Green, format!("[{:.3}] Loaded manifest", t_start.elapsed().as_secs_f32()));

    printcoln(Color::Green, format!("[{:.3}] Building list of files to upload...", t_start.elapsed().as_secs_f32()));
    let filelist = filelist::build_file_list(config.backup_list.as_ref().unwrap());
    printcoln(Color::Green, format!("[{:.3}] Complete ({} files)", t_start.elapsed().as_secs_f32(), filelist.len()));

    let file_queue = Arc::new(Mutex::new(filelist));
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

    // Note that since we supply a bucket name and names are unique, we should get 0 or 1 results
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
    let bucket_id = match buckets.get(0) {
        Some(res) => &res.bucket_id,
        None => {
            printcoln(Color::Red, format!("[{:.3}] No bucket with the name '{}'", t_start.elapsed().as_secs_f32(), bucket_name));
            return;
        }
    };
    printcoln(Color::Green, format!("[{:.3}] {} -> {}", t_start.elapsed().as_secs_f32(), bucket_name, bucket_id));

    printcoln(Color::Green, format!("[{:.3}] Beginning upload", t_start.elapsed().as_secs_f32()));

    let do_encrypt = config.encrypt.unwrap();
    // Load last known nonce
    let mut config_handle = Mutex::new(config);

    // Setup interrupt handler
    let (tx,rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        tx.send(1).unwrap();
    }).expect("Failed to set Ctrl-C handler!");


    // Pool size = num threads = concurrent uploads
    // 1 extra thread is used to sync+upload the manifest every few minutes
    let pool = Pool::new(9);
    let busy_threads = AtomicUsize::new(pool.workers()-1);
    pool.scoped(|scope| {
        // Spawn sync task
        let client = &client;
        let auth = &auth;
        let manifest = &manifest_mutex;
        let upauth = raze::api::b2_get_upload_url(&client, &auth, bucket_id).unwrap();
        let config_handle = &config_handle;
        let busy_threads = &busy_threads;
        scope.execute(move || {
            let mut last_sync = std::time::Instant::now();
            loop {
                // Every 5 secs, check if there are still more items left in queue
                // We need to know, s.t. we can terminate this thread when there is no more work
                // If we received an Ok(n), we received an interrupt signal and should terminate as soon as possible
                let res = rx.recv_timeout(Duration::from_secs(5));

                if res.is_ok() {
                    printcoln(Color::Yellow, format!("[{:.3}] Interrupt received", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] Saving manifest locally...", t_start.elapsed().as_secs_f32()));
                    manifest.lock().unwrap().to_file("manifest.json").unwrap();
                    printcoln(Color::Yellow, format!("[{:.3}] Warning: manifest was only saved locally due to an interruption", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] Using the remote manifest may result in desynchronization", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] If interrupted due to errors, you should run 'retain-rs check' to re-sync local and remote", t_start.elapsed().as_secs_f32()));
                    abort();
                }

                let active_threads = busy_threads.load(Ordering::SeqCst);

                // Check if it's time to sync the manifest
                // Every 5 minutes or if all workers are done
                if last_sync.elapsed().as_secs_f32() >= 60.0*5.0 || active_threads == 0 {
                    if active_threads == 0 {
                        printcoln(Color::Green, format!("[{:.3}] Finalizing manifest sync", t_start.elapsed().as_secs_f32()));
                    }
                    manifest.lock().unwrap().to_file("manifest.json").unwrap();

                    let filesize = std::fs::metadata("manifest.json").unwrap().len();
                    let file = std::fs::File::open("manifest.json").unwrap();

                    let params = raze::api::FileParameters {
                        file_path: "manifest.json", // NEVER mask so we can find it anytime
                        file_size: if do_encrypt { get_encrypted_size(filesize) } else { filesize },
                        content_type: None, // auto
                        content_sha1: Sha1Variant::HexAtEnd,
                        last_modified_millis: 0,
                    };

                    // Delete the existing manifest
                    // This is to prevent clutter (i.e. an old manifest being stored every 5 minutes)
                    raze::api::b2_delete_file_version(&client, &auth, "manifest.json", &manifest.lock().unwrap().remote_id);

                    let file = if do_encrypt {
                        let (start_nonce,allocated) = {
                            let mut n = config_handle.lock().unwrap();
                            let req = get_nonces_required(filesize);
                            let start = n.consume_nonces(req);
                            (start, req)
                        };
                        let file = raze::util::ReadHashAtEnd::wrap(
                            EncryptingReader::wrap(file,
                                                   &key.unwrap(),
                                                   start_nonce,
                                                   allocated));
                        raze::api::b2_upload_file(&client, &upauth, file, params)
                    } else {
                        let file = raze::util::ReadHashAtEnd::wrap(file);
                        raze::api::b2_upload_file(&client, &upauth, file, params)
                    };
                    match file {
                        Ok(info) => {
                            manifest.lock().unwrap().remote_id = info.file_id.unwrap();
                            manifest.lock().unwrap().to_file("manifest.json");
                        },
                        Err(err) => {
                            printcoln(Color::Red, format!("[{:.3}] Error: sync failed", t_start.elapsed().as_secs_f32()));
                            printcoln(Color::Red, format!("[{:.3}] Reason: {:?}", t_start.elapsed().as_secs_f32(), err));
                            if active_threads > 0 {
                                printcoln(Color::Yellow, format!("[{:.3}] Program can auto-recover as long as final sync doesn't fail", t_start.elapsed().as_secs_f32()));
                            } else {
                                printcoln(Color::Red, format!("[{:.3}] Final sync failed!", t_start.elapsed().as_secs_f32()));
                                printcoln(Color::Red, format!("[{:.3}] Some data WILL be de-synced", t_start.elapsed().as_secs_f32()));
                                printcoln(Color::Red, format!("[{:.3}] You should run 'retain-rs backup upload'", t_start.elapsed().as_secs_f32()));
                                printcoln(Color::Red, format!("[{:.3}] Followed by 'retain-rs clean delete' (without fast)", t_start.elapsed().as_secs_f32()));
                            }
                        }
                    }
                    last_sync = std::time::Instant::now();
                    if active_threads == 0 {
                        break;
                    }
                }
            }
        });

        // Spawn upload tasks
        for _ in 0..pool.workers()-1 {
            let files = file_queue.clone();

            let manifest = &manifest_mutex;
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
                            // Decrement busy threads by 1
                            busy_threads.fetch_sub(1, Ordering::SeqCst);
                            break;
                        }
                    };

                    // Check if the file is already backed up and if it has been modified since
                    // Get modified time and filesize by querying metadata
                    let do_upload: bool;
                    let metadata = match std::fs::metadata(&path) {
                        Ok(m) => m,
                        Err(e) => {
                            println!("Failed to get metadata, skipping file ({:?})", e);
                            continue;
                        }
                    };
                    let modified_time = match metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH) {
                        Ok(v) => v.as_millis() as u64, // Convert seconds to milliseconds
                        Err(_e) => 0u64
                    };
                    let filesize = metadata.len(); // Used later as well

                    // Returns 'None' if entry hasn't been uploaded
                    match manifest.lock().unwrap().get_from_path(&path) {
                        Some(t) => {
                            do_upload = modified_time > t.0;
                        },
                        None => {
                            do_upload = true;
                        }
                    }
                    if !do_upload {
                        continue;
                    }
                    manifest.lock().unwrap().update_timestamp(&path, modified_time);

                    // Get the name to use in B2
                    // Either masked name or web-compatible path
                    let name_in_b2 = manifest.lock().unwrap().get_mask(&path, modified_time).1;

                    //println!("Uploading {:?} -> {:?}", path, name_in_b2);
                    println!("Uploading {}", path);

                    // Try uploading up to 5 times
                    for attempts in 0..5 {
                        let file = match std::fs::File::open(&path) {
                            Ok(f) => f,
                            Err(e) => {
                                println!("Failed to open file {:?} ({:?}) - It will not be uploaded", path, e);
                                break;
                            }
                        };

                        let params = raze::api::FileParameters {
                            file_path: &name_in_b2,
                            file_size: if do_encrypt { get_encrypted_size(filesize) } else { filesize },
                            content_type: None, // auto
                            content_sha1: Sha1Variant::HexAtEnd,
                            last_modified_millis: modified_time,
                        };

                        let (start_nonce,allocated) = {
                            let mut n = config_handle.lock().unwrap();
                            let req = get_nonces_required(filesize);
                            let start = n.consume_nonces(req);
                            (start, req)
                        };
                        // println!("Using nonce {} through {} ({})", start_nonce, start_nonce+allocated-1, allocated);

                        // TODO Handle bandwidth limiting by wrapping in throttled reader
                        let result = if do_encrypt {
                            let file = raze::util::ReadHashAtEnd::wrap(
                                EncryptingReader::wrap(file,
                                                        &key.unwrap(),
                                                        start_nonce,
                                                        allocated));
                            raze::api::b2_upload_file(&client, &upauth, file, params)
                        } else {
                            let file = raze::util::ReadHashAtEnd::wrap(file);
                            raze::api::b2_upload_file(&client, &upauth, file, params)
                        };

                        match result {
                            Ok(_) => break,
                            Err(e) => {
                                println!("Upload failed: {:?}", e);
                                match e {
                                    raze::Error::B2Error(e) => {
                                        // TODO: consider adding re-auth here
                                        // Both 'auth' and 'upauth' can expire
                                        println!("Reason: {:?}", e);
                                    },
                                    _ => (),
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
                    }
                }
            });
        }
    });

    // The manifest is automatically written to disk and synced to B2
    // This happens every 5 minutes while uploading and when the backup finishes

    printcoln(Color::Green, format!("[{:.3}] Backup Completed!", t_start.elapsed().as_secs_f32()));
}