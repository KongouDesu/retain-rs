use crate::config::Config;
use clap::ArgMatches;
use crate::colorutil::printcoln;
use termcolor::Color;
use crate::filelist;
use chacha20poly1305::Key;
use raze::api::{ListBucketParams, Sha1Variant, B2DownloadFileByNameParams, B2GetDownloadAuthParams, B2FileInfo};
use std::time::{Duration, UNIX_EPOCH};
use std::fs::metadata;
use std::path::Path;
use crate::encryption::{get_encrypted_size, get_nonces_required};
use crate::encryption::reader::EncryptingReader;
use reqwest::blocking::Response;
use raze::Error;
use crate::manifest::FileManifest;
use scoped_pool::Pool;
use std::sync::{Arc, Mutex};

// Extracts params from `args`, then calls `clean`
pub fn clean_using_clap(config: &mut Config, args: Option<&ArgMatches>) {
    let args = args.unwrap();

    let mode = args.value_of("mode").unwrap(); // Can't fail: enforced by clap
    let force = args.is_present("force");
    let fast = args.is_present("fast");

    clean(config, mode, force, fast);
}

// Ensures the local manifest matches the files present in remote
// Cleans up all files in remote that can't be found in the backup-list
pub fn clean<T: AsRef<str>>(config: &mut Config, mode: T, force: bool, fast: bool) {
    let t_start = std::time::Instant::now();
    let mode = mode.as_ref();

    if mode == "delete" && fast {
        printcoln(Color::Red, "Error: cannot use mode 'delete' with --fast");
        printcoln(Color::Red, "Either use mode 'hide' or do not use --fast");
        return;
        // Technical reason:
        // 'Hide' takes in a file name, which is what we store
        // 'Delete' takes in a file id
        // When doing a fast clean, we do not retrieve all files and thus do not have the ids
        // When we do a "slow" clean, we _do_ retrieve them
        // Since "fast" deliberately does NOT fetch to be fast, we cannot use delete as a result
    }

    printcoln(Color::Yellow, "Starting cleanup");
    printcoln(Color::Yellow, "Note: if interrupted, you should re-run WITHOUT the 'fast' option");

    // Start doing all the preparation work necessary
    // This will authenticate, resolve bucket name, get the encryption settings
    // Load the manifest and build the file list

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
    printcoln(Color::Green, format!("[{:.3}] Loaded manifest", t_start.elapsed().as_secs_f32()));

    printcoln(Color::Green, format!("[{:.3}] Building list of files...", t_start.elapsed().as_secs_f32()));
    let filelist = filelist::build_file_list(config.backup_list.as_ref().unwrap());
    printcoln(Color::Green, format!("[{:.3}] Complete ({} files)", t_start.elapsed().as_secs_f32(), filelist.len()));

    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(60)).build().unwrap();
    printcoln(Color::Green, format!("[{:.3}] Authenticating...", t_start.elapsed().as_secs_f32()));

    let keystring = format!("{}:{}", config.app_key_id.as_ref().unwrap(), config.app_key.as_ref().unwrap());
    let auth = match raze::api::b2_authorize_account(&client,&keystring) {
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

    let do_encrypt = config.encrypt.unwrap();
    // Prep work done

    // Check if the remote manifest.json is newer than the local one
    // If it is, abort
    // This is skipped if the --force flag is applied
    if !force {
        let modified_local = match metadata("manifest.json").unwrap().modified().unwrap().duration_since(UNIX_EPOCH) {
            Ok(v) => v.as_secs() * 1000,
            Err(_) => 0,
        };

        // Get info on the remote manifest
        // We need this to check when it was modified vs when local was modified
        let remote_manifest_info = match raze::api::b2_get_file_info(&client, &auth, &manifest.remote_id) {
            Ok(info) => info,
            Err(err) => {
                printcoln(Color::Red, format!("[{:.3}] Failed to get info on remote manifest.json", t_start.elapsed().as_secs_f32()));
                printcoln(Color::Red, format!("[{:.3}] Make sure you have the right bucket and have backed up at least once before",
                                              t_start.elapsed().as_secs_f32()));
                printcoln(Color::Red, format!("[{:.3}] Reason: {:?}", t_start.elapsed().as_secs_f32(), err));
                return;
            }
        };

        // Check if remote is more recent
        if remote_manifest_info.modified() > modified_local {
            printcoln(Color::Red, format!("[{:.3}] Error: remote manifest is more recent than local", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] This is likely caused by either:", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] 1. More recent backup from a different setup/location", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] 2. Use of an old manifest.json, e.g. manifest.json.old", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] If you want to proceed with an old manifest, use --force", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] Otherwise, you likely want to 'backup download' first, or use a different bucket", t_start.elapsed().as_secs_f32()));
            return;
        } else {
            printcoln(Color::Green, format!("[{:.3}] Local manifest is up-to-date", t_start.elapsed().as_secs_f32()));
        }
    }



    // Done checking (or skipped) manifest.json recency check
    // Now, remove all entries in manifest that cannot be found locally
    // This will check if each file in manifest.json can be found on local storage
    // Those that aren't found are removed from the manifest.json
    let mut removed_files = vec![]; // Save the files we removed
    let mut i = 0;
    while i != manifest.files.len() {
        if !filelist.contains(&manifest.files[i].path) || !Path::new(&manifest.files[i].path).exists() {
            removed_files.push(manifest.files.remove(i).path);
        } else {
            i += 1;
        }
    }
    manifest.to_file("manifest.json").expect("Failed to save manifest.json");

    // Now that we know all files in the manifest are present, clean up remote
    // There are 2 ways this can be done
    // 1. Fast is ENABLED: Hide only files we just removed from local manifest
    // 2. Fast is DISABLED: Get list of all files from B2, then hide the ones we can't find
    // Note that 1. will miss files is manifest is de-synced

    if fast { // Fast enabled
        println!("Fast track!");
        let pool = Pool::new(8);
        println!("Hiding {} files", &removed_files.len());
        let queue = Arc::new(Mutex::new(removed_files));

        pool.scoped(|scope| {
            for _ in 0..pool.workers() {
                let queue = queue.clone();
                let client = &client;
                let auth = &auth;
                scope.execute(move || {
                    let mut next = queue.lock().unwrap().pop();
                    while next.is_some() {
                        let file = next.unwrap();
                        // Note: delete is unsupported; See top of file
                        printcoln(Color::White, format!("Hiding {}", &file));
                        raze::api::b2_hide_file(&client, &auth, bucket_id, file);
                        next = queue.lock().unwrap().pop();
                    }
                });
            }
        });
    } else { // Fast disabled
        // First, we need to retrieve the list of files on remote
        printcoln(Color::Yellow, format!("[{:.3}] Retrieving list of remote files, this may take a while...",  t_start.elapsed().as_secs_f32()));
        let mut remote_files = match raze::util::list_all_files(&client, &auth, bucket_id, 10000) {
            Ok(f) => f,
            Err(e) => {
                printcoln(Color::Red, format!("[{:.3}] Failed to retrieve file list ({:?})", t_start.elapsed().as_secs_f32(), e));
                return;
            },
        };

        // Create a sorted list of masks, since remote files are known by their mask
        // This lets us binary search for them
        let mut mask_list = Vec::with_capacity(manifest.files.len());
        for elem in &manifest.files {
            mask_list.push(elem.mask.clone());
        }
        mask_list.sort();
        // We remove manifest.json from the remote file list to make sure we don't remove it
        // If we don't do this, we will inadvertently remove the manifest.json in B2, since it is
        // never going to be in the manifest's file list
        let sf = raze::api::B2FileInfo {
            file_name: "manifest.json".to_string(),
            ..Default::default()
        };
        if let Ok(idx) = remote_files.binary_search(&sf) {
            remote_files.remove(idx);
        };
        // Now, for each remote file, check if we have a matching mask in our local manifest
        // If we have a match, it means the file can be found on our local storage -- do nothing
        // If it can't be found, the file is either deleted or we de-synced and lost track of it at some point
        // In that case, either hide or delete it, based on the passed setting
        let pool = Pool::new(8);
        let queue = Arc::new(Mutex::new(remote_files));
        pool.scoped(|scope| {
            for _ in 0..pool.workers() {
                let queue = queue.clone();
                let client = &client;
                let auth = &auth;
                let mask_list = &mask_list;
                scope.execute(move || {
                    let mut next = queue.lock().unwrap().pop();
                    while next.is_some() {
                        let file = next.unwrap();
                        if let Err(_) = mask_list.binary_search(&file.file_name) {
                            match mode {
                                "hide" => {
                                    printcoln(Color::White, format!("Hiding {}", &file.file_name));
                                    raze::api::b2_hide_file(&client, &auth, bucket_id, file.file_name);
                                },
                                "delete" => {
                                    printcoln(Color::White, format!("Deleting {}", &file.file_name));
                                    raze::api::b2_delete_file_version(&client, &auth, file.file_name, file.file_id.unwrap());
                                }
                                _ => unreachable!()
                            }
                        }
                        next = queue.lock().unwrap().pop();
                    }
                });
            }
        });
    }

    // Done hiding/deleting
    // Sync the modified manifest
    printcoln(Color::Green, format!("[{:.3}] Syncing manifest...", t_start.elapsed().as_secs_f32()));
    // Note: manifest.json already saved to disk at this point
    let filesize = std::fs::metadata("manifest.json").unwrap().len();
    let file = std::fs::File::open("manifest.json").unwrap();

    let params = raze::api::FileParameters {
        file_path: "manifest.json", // NEVER mask so we can find it anytime
        file_size: if do_encrypt { get_encrypted_size(filesize) } else { filesize },
        content_type: None, // auto
        content_sha1: Sha1Variant::HexAtEnd,
        last_modified_millis: 0,
    };

    let upauth = raze::api::b2_get_upload_url(&client, &auth, bucket_id).expect("Failed to get upload auth");

    let file = if do_encrypt {
        let (start_nonce,allocated) = {
            let req = get_nonces_required(filesize);
            let start = config.consume_nonces(req);
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
    // Check status / save remote id for later
    match file {
        Ok(info) => {
            manifest.remote_id = info.file_id.unwrap();
            manifest.to_file("manifest.json").unwrap();
        },
        Err(err) => {
            printcoln(Color::Red, format!("[{:.3}] Error: sync failed", t_start.elapsed().as_secs_f32()));
            printcoln(Color::Red, format!("[{:.3}] Reason: {:?}", t_start.elapsed().as_secs_f32(), err));
        }
    }

    printcoln(Color::Green, format!("[{:.3}] Cleanup finished", t_start.elapsed().as_secs_f32()));

}