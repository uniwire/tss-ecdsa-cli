#![allow(non_snake_case)]
//#![feature(proc_macro_hygiene, decl_macro)]

extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

use std::env;
use std::fs;
use clap::{App, AppSettings, Arg, SubCommand};

use common::{hd_keys, manager};

use protocols::ecdsa;
use protocols::eddsa;
use crate::common::{export_keys, MAX_FIRST_PRIMES};
use crate::protocols::HdImplementation;

mod common;
mod protocols;

#[cfg(test)]
mod tests;

fn main() {
    let args: Vec<String> = env::args().collect();
    match run_main(args) {
        Ok(outcome) => println!("{}", outcome),
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1);
        }
    };
}

fn run_main<I, T>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let matches = App::new("TSS CLI Utility")
        .version("0.2.2")
        .author("Kaspars Sprogis <darklow@gmail.com>")
//        .about("")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommands(vec![
            SubCommand::with_name("manager").about("Run state manager"),
            SubCommand::with_name("keygen").about("Run keygen")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Target keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager. E.g. http://127.0.0.2:8002"))
                .arg(Arg::with_name("room_id")
                    .short("r")
                    .long("room_id")
                    .required(false)
                    .takes_value(true)
                    .help("Optional unique string to avoid interference between two or more \
                    groups of parties doing keygen concurrently."))
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .possible_values(&["eddsa", "ecdsa"])
                    .default_value("ecdsa")
                    .help("Either ecdsa (default) or eddsa")),
            SubCommand::with_name("pubkey").about("Get X,Y of a pub key")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path (Optional)"))
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .possible_values(&["ecdsa", "eddsa"])
                    .default_value("ecdsa")
                    .help("Either ecdsa (default) or eddsa"))
                .arg(Arg::with_name("chain_code")
                    .short("c")
                    .long("cc")
                    .takes_value(true)
                    .help("Hex representation of chain_code"))
                .arg(Arg::with_name("hd")
                    .short("h")
                    .long("hd")
                    .takes_value(true)
                    .default_value("legacy")
                    .possible_values(&["legacy", "bip32"])
                    .help("HD key derivation variant.")),
            SubCommand::with_name("sign").about("Run signer")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("message")
                    .index(3)
                    .required(true)
                    .takes_value(true)
                    .help("Message to sign in hex format. It has to be at least 32 chars long."))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path"))
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .possible_values(&["ecdsa", "eddsa"])
                    .default_value("ecdsa")
                    .help("Either ecdsa (default) or eddsa"))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager"))
                .arg(Arg::with_name("chain_code")
                    .short("c")
                    .long("cc")
                    .takes_value(true)
                    .help("Hex representation of chain_code"))
                .arg(Arg::with_name("hd")
                    .short("h")
                    .long("hd")
                    .takes_value(true)
                    .default_value("legacy")
                    .possible_values(&["legacy", "bip32"])
                    .help("HD key derivation variant.")),
            SubCommand::with_name("keygen-all").about("Run keygen for both ECDSA and EdDSA sequentially, producing a single combined key file")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Target combined keys file (e.g. keys1.json)"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager. E.g. http://127.0.0.2:8002"))
                .arg(Arg::with_name("room_id")
                    .short("r")
                    .long("room_id")
                    .required(false)
                    .takes_value(true)
                    .help("Optional unique string to avoid interference between two or more \
                    groups of parties doing keygen concurrently.")),
            SubCommand::with_name("convert_curv_07_to_09").about("Convert format of store files from v0.1.0 to v0.2.0")
                .arg(Arg::with_name("input_file")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Source key file to read and convert."))
                .arg(Arg::with_name("output_file")
                    .required(true)
                    .index(2)
                    .takes_value(true)
                    .help("Output keys file to which converted file will be written.")),
            SubCommand::with_name("export").about("Exports the key for recovery.")
                .arg(Arg::with_name("input_dir")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Source directory containing key files.")),
            SubCommand::with_name("safety_check").about("Checks a given key file against first n primes")
                .arg(Arg::with_name("input_file")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Source keys file"))
                .arg(Arg::with_name("max_first")
                    .required(false)
                    .index(2)
                    .takes_value(true)
                    .help("How many prime numbers should be checked?"))
        ])
        .get_matches_from(args);

    let rocket_default_port = env::var("ROCKET_PORT").unwrap_or("8000".to_string());
    let manager_default_address = "http://127.0.0.1:".to_string() + rocket_default_port.as_str();

    match matches.subcommand() {
        ("pubkey", Some(sub_matches)) | ("sign", Some(sub_matches)) => {
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("");
            let path = sub_matches.value_of("path").unwrap_or("");
            let message_str = sub_matches.value_of("message").unwrap_or("");
            let curve = sub_matches.value_of("algorithm").unwrap_or("ecdsa");
            let hd_variant = sub_matches.value_of("hd").unwrap_or("bip32");

            let manager_addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or(manager_default_address.as_str())
                .to_string();
            // Parse threshold params
            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();
            let action = matches.subcommand_name().unwrap();
            let result = match curve {
                "ecdsa" => ecdsa::run_pubkey_or_sign(
                    action,
                    keysfile_path,
                    path,
                    message_str,
                    manager_addr,
                    params,
                    match hd_variant {
                        "legacy" => HdImplementation::Legacy,
                        _ => HdImplementation::Bip32,
                    },
                ),
                "eddsa" => match action {
                    "sign" => eddsa::sign(
                        manager_addr,
                        keysfile_path.to_string(),
                        params,
                        message_str.to_string(),
                        path,
                        match hd_variant {
                            "legacy" => HdImplementation::Legacy,
                            _ => HdImplementation::Bip32,
                        },
                    ),
                    "pubkey" => eddsa::run_pubkey(
                        keysfile_path,
                        path,
                        match hd_variant {
                            "legacy" => HdImplementation::Legacy,
                            _ => HdImplementation::Bip32,
                        },
                    ),
                    _ => Err("".to_string()) // action is already checked, so this never happens
                }
                _ => Err("Invalid algorithm".to_string()) // Possible values specified, thus never happens
            }?;
            Ok(result.to_string())
        }
        ("manager", Some(_matches)) => {
            let _ = manager::run_manager();
            Ok("Manager started.".to_string())
        }
        ("keygen", Some(sub_matches)) => {
            let addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or(manager_default_address.as_str())
                .to_string();
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();
            let curve = sub_matches.value_of("algorithm").unwrap_or("ecdsa");
            let room_id = sub_matches.value_of("room_id").unwrap_or("").to_string();
            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();
            let keygen_json = match curve {
                "ecdsa" => ecdsa::keygen::run_keygen(&addr, &params, room_id),
                "eddsa" => eddsa::keygen::run_keygen(&addr, &params, room_id),
                _ => Err("Invalid curve type specified.".to_string())
            }
                .map_err(|error| format!("Command keygen failed with error: {}", error))?;

            fs::write(&keysfile_path, &keygen_json)
                .map_err(|e| format!("Unable to save keys file: {}", e))?;

            Ok(format!("Keys data written to file: {:?}", keysfile_path))
        }
        ("keygen-all", Some(sub_matches)) => {
            let addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or(manager_default_address.as_str())
                .to_string();
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();
            let room_id = sub_matches.value_of("room_id").unwrap_or("").to_string();
            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();

            // Step 1: Run ECDSA keygen
            eprintln!("{{\"event\":\"phase\",\"phase\":\"ecdsa\",\"phase_num\":1,\"total_phases\":2}}");
            let ecdsa_json = ecdsa::keygen::run_keygen(&addr, &params, room_id.clone())
                .map_err(|error| format!("ECDSA keygen failed: {}", error))?;

            // Step 2: Run EdDSA keygen
            eprintln!("{{\"event\":\"phase\",\"phase\":\"eddsa\",\"phase_num\":2,\"total_phases\":2}}");
            let eddsa_json = eddsa::keygen::run_keygen(&addr, &params, room_id)
                .map_err(|error| format!("EdDSA keygen failed: {}", error))?;

            // Step 3: Merge into combined format {"ecdsa": ..., "eddsa": ...}
            let ecdsa_value: serde_json::Value = serde_json::from_str(&ecdsa_json)
                .map_err(|e| format!("Failed to parse ECDSA keygen output: {}", e))?;
            let eddsa_value: serde_json::Value = serde_json::from_str(&eddsa_json)
                .map_err(|e| format!("Failed to parse EdDSA keygen output: {}", e))?;

            // Extract party_index from ECDSA keygen output (4th element, index 3)
            let party_index = ecdsa_value
                .as_array()
                .and_then(|arr| arr.get(3))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "Failed to extract party_index from ECDSA keygen output".to_string())?;

            let combined = serde_json::json!({
                "ecdsa": ecdsa_value,
                "eddsa": eddsa_value,
            });

            let combined_json = serde_json::to_string(&combined)
                .map_err(|e| format!("Failed to serialize combined keys: {}", e))?;

            // Append _{party_index} before .json extension
            let final_path = if keysfile_path.ends_with(".json") {
                format!("{}_{}.json", &keysfile_path[..keysfile_path.len() - 5], party_index)
            } else {
                format!("{}_{}", keysfile_path, party_index)
            };

            fs::write(&final_path, combined_json)
                .map_err(|e| format!("Unable to save combined keys file: {}", e))?;

            Ok(format!("Combined keys (ECDSA + EdDSA) written to file: {:?}", final_path))
        }
        ("convert_curv_07_to_09", Some(sub_matches)) => {
            let source_path = sub_matches.value_of("input_file").unwrap_or("").to_string();
            let destination_path = sub_matches.value_of("output_file").unwrap_or("").to_string();

            ecdsa::curv7_conversion::convert_store_file(source_path, destination_path)
        }
        ("safety_check", Some(sub_matches)) => {
            let source_path = sub_matches.value_of("input_file").unwrap_or("").to_string();
            let limit = sub_matches.value_of("max_first").unwrap_or(MAX_FIRST_PRIMES.to_string().as_str()).parse::<usize>().unwrap();

            ecdsa::check_key_file(source_path.as_str(), limit)
                .map_err(|error| format!("Couldn't check key file, error: {}", error))
                .map(|result| {
                    if result {
                        "Key file check failed.".to_string()
                    }
                    else {
                        "Key file check successful!".to_string()
                    }
            })
        }
        ("export", Some(sub_matches)) => {
            let source_dir = sub_matches.value_of("input_dir")
                .unwrap_or("")
                .to_string();
            let result = export_keys(source_dir);
            Ok(result)
        }
        _ => Err("Invalid command specified.".to_string())
    }
}
