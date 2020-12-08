use crate::config::Config;
use crate::colorutil::printcoln;
use termcolor::Color;
use chacha20poly1305::Key;
use std::sync::{Mutex, mpsc};
use raze::api::{ListBucketParams, B2DownloadFileByNameParams};
use crate::manifest::FileManifest;
use std::fs::File;
use std::io::Write;
use crate::encryption::writer::DecryptingWriter;
use scoped_pool::Pool;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use std::time::Duration;
use std::process::abort;

// This will start retrieving files previously backed up
// This will:
// 1. Check that everything in the config is set
// 2. Read the manifest.json
// 3. For each file in the manifest, check if it is present on the drive
// 4. All files not present are retrieved from remote
// 5. If the file is found, check if the remote version is more recent
// 6. If it is more recent, replace existing file with remote one
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

    // Get encryption status
    let mut key = None;
    match config.encrypt.unwrap() {
        true => {
            printcoln(Color::Green, "Encryption is enabled");
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

    // Authenticate
    // We need to do this early in order to retrieve manifest.json from remote
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

    // Get the bucket we're using
    // This is were manifest.json is and were we download files from
    // Note that since we supply a bucket name and names are unique, we should get 0 or 1 results
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
    let bucket_id = match buckets.get(0) {
        Some(res) => &res.bucket_id,
        None => {
            printcoln(Color::Red, format!("[{:.3}] No bucket with the name '{}'", t_start.elapsed().as_secs_f32(), bucket_name));
            return;
        }
    };
    printcoln(Color::Green, format!("[{:.3}] {} -> {}", t_start.elapsed().as_secs_f32(), bucket_name, bucket_id));


    printcoln(Color::Green, format!("[{:.3}] Retrieving remote file manifest", t_start.elapsed().as_secs_f32()));
    let params = B2DownloadFileByNameParams {
        bucket_name: config.bucket_name.as_ref().unwrap().to_string(),
        file_name: "manifest.json".to_string(),
        authorization: None // Uses B2auth as fallback
    };
    // Try to download the remote manifest.json
    let mut manifest = match raze::api::b2_download_file_by_name(&client, &auth, params) {
        Ok(response) => {
            // Move local manifest.json to manifest.json.old
            printcoln(Color::Green, format!("[{:.3}] Backing up old manifest...", t_start.elapsed().as_secs_f32()));
            std::fs::rename("manifest.json","manifest.json.old");

            // Create new manifest.json and fill it with the response we just got
            printcoln(Color::Green, format!("[{:.3}] Loading new manifest", t_start.elapsed().as_secs_f32()));
            let mut file = match File::create("manifest.json") {
                Ok(f) => f,
                Err(err) => {
                    printcoln(Color::Red, format!("[{:.3}] Failed to open manifest.json ({:?})", t_start.elapsed().as_secs_f32(), err));
                    return;
                }
            };
            // If encryption is on, decrypt the remote data first
            match config.encrypt.unwrap() {
                true => {
                    let mut writer = DecryptingWriter::target(file, &key.unwrap());
                    writer.write_all(&response.bytes().unwrap());
                    writer.flush();
                },
                false => {
                    file.write_all(&response.bytes().unwrap());
                    file.flush();
                }
            }


            // Try to load the manifest
            match FileManifest::from_file("manifest.json") {
                Ok(fm) => fm,
                Err(err) => {
                    printcoln(Color::Red, format!("[{:.3}] Failed to load remote file manifest ({})", t_start.elapsed().as_secs_f32(), err));
                    printcoln(Color::Red, format!("[{:.3}] This should not happen. Falling back to local manifest!", t_start.elapsed().as_secs_f32()));
                    match FileManifest::from_file("manifest.json.old") {
                        Ok(fm) => {
                            std::fs::rename("manifest.json.old", "manifest.json");
                            fm
                        },
                        Err(err2) => {
                            std::fs::rename("manifest.json.old", "manifest.json");
                            printcoln(Color::Red, format!("[{:.3}] Failed to load LOCAL file manifest ({})", t_start.elapsed().as_secs_f32(), err2));
                            printcoln(Color::Red, format!("[{:.3}] LOCAL and REMOTE manifests are invalid", t_start.elapsed().as_secs_f32()));
                            printcoln(Color::Red, format!("[{:.3}] This should never happen!", t_start.elapsed().as_secs_f32()));
                            printcoln(Color::Red, format!("[{:.3}] Is manifest.json missing or corrupted?", t_start.elapsed().as_secs_f32()));
                            printcoln(Color::Red, format!("[{:.3}] Was 'download' ran before 'init'?", t_start.elapsed().as_secs_f32()));
                            return;
                        }
                    }
                }
            }
        },
        Err(err) => {
            printcoln(Color::Red, format!("[{:.3}] Failed to retrieve remote manifest ({:?})", t_start.elapsed().as_secs_f32(), err));
            printcoln(Color::Red, format!("[{:.3}] This should not happen. Falling back to local manifest!", t_start.elapsed().as_secs_f32()));
            match FileManifest::from_file("manifest.json") {
                Ok(fm) => {
                    fm
                },
                Err(err2) => {
                    printcoln(Color::Red, format!("[{:.3}] Failed to load LOCAL file manifest ({})", t_start.elapsed().as_secs_f32(), err2));
                    printcoln(Color::Red, format!("[{:.3}] REMOTE could not be retrieved and could not load LOCAL", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Red, format!("[{:.3}] This should never happen!", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Red, format!("[{:.3}] Is manifest.json missing or corrupted?", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Red, format!("[{:.3}] Was 'download' ran before 'init'?", t_start.elapsed().as_secs_f32()));
                    return;
                }
            }
        }
    };

    let manifest_mutex = Mutex::new(&mut manifest);
    printcoln(Color::Green, format!("[{:.3}] Loaded manifest", t_start.elapsed().as_secs_f32()));


    // Setup interrupt handler
    let (tx,rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        tx.send(1).unwrap();
    }).expect("Failed to set Ctrl-C handler!");

    let pool = Pool::new(9);
    // Amount of threads downloading/writing files
    let busy_threads = AtomicUsize::new(pool.workers()-1);
    // Whether or not threads can open new files for writing
    let allow_open_file = AtomicBool::new(true);
    // How many threads currently have a file open for writing
    let open_files = AtomicUsize::new(0);

    // This pool consists of 2 parts
    // 1. A thread watching for interrupts (Ctrl-C) and if the pool is done
    // 2. 'n' threads each downloading a file
    // Each download thread pops elements from the file manifest,
    // and tries to find the the local file matching the entry
    // If it exists, it compares modified times. If remote is more recent, local is replaced
    // Otherwise, the local version is kept
    // If the local file does not exist, it is retrieved from remote
    pool.scoped(|scope| {
        // Spawn sync task
        let client = &client;
        let auth = &auth;
        let manifest = &manifest_mutex;
        let busy_threads = &busy_threads;
        let allow_open_file = &allow_open_file;
        let open_files = &open_files;
        scope.execute(move || {
            loop {
                // Every 5 secs, check if there are still more items left in queue
                // We need to know, s.t. we can terminate this thread when there is no more work
                // If we received an Ok(n), we received an interrupt signal and should terminate as soon as possible
                let res = rx.recv_timeout(Duration::from_secs(5));

                if res.is_ok() {
                    printcoln(Color::Yellow, format!("[{:.3}] Interrupt received", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] Waiting for pending writes - This should only take a few seconds", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] Please be patient if the files are very large and/or we're in debug mode", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] WARNING: INTERRUPTING THIS _WILL_ LEAVE BROKEN FILES!", t_start.elapsed().as_secs_f32()));
                    printcoln(Color::Yellow, format!("[{:.3}] IF INTERRUPTED NOW, YOU MUST MANUALLY CHECK THE LAST 8 FILES FOR CORRUPTION", t_start.elapsed().as_secs_f32()));
                    // Disallow opening of new files
                    allow_open_file.swap(false, Ordering::SeqCst);
                    // Empty manifest files means empty queue of files to check
                    manifest.lock().unwrap().files.clear();
                    // We must now wait until open_files = 0
                    while open_files.load(Ordering::SeqCst) > 0 {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    // No files are open and no new ones can be opened
                    // Exit the program
                    printcoln(Color::Green, format!("[{:.3}] Exit OK - No issues detected", t_start.elapsed().as_secs_f32()));
                    abort();
                }

                // If all threads are done, exit this thread and with it the entire pool
                let active_threads = busy_threads.load(Ordering::SeqCst);
                if active_threads == 0 {
                    break;
                }
            }
        });

        // Spawn download tasks
        for i in 0..pool.workers()-1 {
            let manifest = &manifest_mutex;

            scope.execute(move || {
                loop {
                    // Try to get a new entry
                    let p = {
                        manifest.lock().unwrap().files.pop()
                    };
                    let entry = match p {
                        Some(e) => e,
                        None => {
                            // List is empty, nothing more to upload
                            // Decrement busy threads by 1
                            busy_threads.fetch_sub(1, Ordering::SeqCst);
                            break;
                        }
                    };

                    // Check metadata
                    let mut do_download = false;
                    match std::fs::metadata(&entry.path) {
                        Ok(meta) => {
                            let modified_time = match meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH) {
                                Ok(v) => v.as_millis() as u64, // Convert seconds to milliseconds
                                Err(_e) => 0u64
                            };
                            if modified_time < entry.timestamp {
                                do_download = true;
                            }
                        },
                        Err(e) => {
                            do_download = true;
                        }
                    };
                    if !do_download {
                        continue;
                    }

                    println!("Downloading {:?} -> {:?}", entry.mask, entry.path);

                    // Try up to 5 times
                    for attempts in 0..5 {
                        let params = B2DownloadFileByNameParams {
                            bucket_name: bucket_name.to_string(),
                            file_name: entry.mask.to_string(),
                            authorization: None // Falls back to B2Auth
                        };

                        let result = raze::api::b2_download_file_by_name(&client, &auth, params);
                        match result {
                            Ok(response) => {
                                // We just downloaded the file, now we must handle writing and decrypting it
                                // First of all, indicate we intend to open a file
                                // Note that this _must_ be done before checking if we're allowed to actually open the file
                                // in order to avoid a race condition
                                open_files.fetch_add(1, Ordering::SeqCst);

                                // Check if we are allowed to write this file
                                if !allow_open_file.load(Ordering::SeqCst) {
                                    // We cannot open files (and never will be allowed to again)
                                    // This happens when the program is interrupted, e.g. Ctrl-C was pressed
                                    // In this case, we end the thread since it's gonna die shortly anyways
                                    open_files.fetch_sub(1, Ordering::SeqCst);
                                    busy_threads.fetch_sub(1, Ordering::SeqCst);
                                    return;
                                };

                                // Create all directories needed if they cannot be found
                                match std::path::Path::new(&entry.path).parent() {
                                    Some(p) => {
                                        std::fs::create_dir_all(p);
                                    },
                                    None => (),
                                };
                                // Try to create/overwrite the file
                                let mut file = match File::create(&entry.path) {
                                    Ok(f) => f,
                                    Err(err) => {
                                        println!("Failed to create/open {} - Retrying ({:?})", entry.path, err);
                                        open_files.fetch_sub(1, Ordering::SeqCst);
                                        continue;
                                    }
                                };
                                // Either decrypt+write or just write the file
                                match config.encrypt.unwrap() {
                                    true => {
                                        let mut writer = DecryptingWriter::target(file, &key.as_ref().unwrap());
                                        writer.write_all(&response.bytes().unwrap());
                                        writer.flush();
                                    },
                                    false => {
                                        file.write_all(&response.bytes().unwrap());
                                        file.flush();
                                    }
                                };

                                // File closed, keep track
                                open_files.fetch_sub(1, Ordering::SeqCst);

                            },
                            Err(e) => {
                                println!("Download failed: {:?}", e);
                                match e {
                                    raze::Error::B2Error(e) => {
                                        // TODO: consider adding re-auth here
                                        // Both 'auth' and 'upauth' can expire
                                        println!("Reason: {:?}", e);
                                    },
                                    _ => (),
                                }

                                if attempts == 4 {
                                    println!("Failed to download {:?} after 5 attempts", entry.path);
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

    printcoln(Color::Green, format!("[{:.3}] Download Completed!", t_start.elapsed().as_secs_f32()));

}