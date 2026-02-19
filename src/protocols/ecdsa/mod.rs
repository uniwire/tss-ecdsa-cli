pub mod keygen;
pub mod signer;
pub mod curv7_conversion;

extern crate serde_json;
use serde_json::{json, Value};

use std::fs;
use crate::common::{hd_keys, is_divisible_by_first_n_primes, validate_hex_string, validate_vss_scheme_vector, Params};

//use aes_gcm::aead::{NewAead};

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;

use curv::{arithmetic::traits::Converter};
use curv::arithmetic::Zero;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, SharedKeys
};
use crate::protocols::{HdImplementation, CHAIN_CODE_ERROR_IN_FILE, INVALID_FRAGMENT_FILE_ERROR, INVALID_MASTER_PUBLIC_KEY_IN_FILE, INVALID_MESSAGE_STRING_ERROR, PARTY_ID_ERROR_IN_FILE, PARTY_INDEX_ERROR_IN_FILE, PRIVATE_KEY_ERROR_IN_FILE, PUBLIC_KEY_ERROR_IN_FILE, SHARED_KEY_ERROR_IN_FILE};

//pub type Key = String;
pub static CURVE_NAME: &str = "ECDSA";
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

pub struct ECDSAParameters {
    party_key: Keys,
    chain_code: FE,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    pub(crate) paillier_key_vec: Vec<EncryptionKey>,
    pub master_public_key: GE,
}

impl ECDSAParameters {

    /// Parse ECDSA parameters from a raw JSON string.
    pub fn read_from_string(data: &str) -> Result<ECDSAParameters, String> {
        match serde_json::from_str(data) {
            Ok(params) => {
                let (party_key, chain_code, shared_keys, party_id, vss_scheme_vec, paillier_key_vec, master_public_key): (
                    Keys,
                    Scalar<Secp256k1>,
                    SharedKeys,
                    u16,
                    Vec<VerifiableSS<Secp256k1>>,
                    Vec<EncryptionKey>,
                    GE,
                ) = params;

                let ecdsa_params = ECDSAParameters {
                    party_key,
                    chain_code,
                    shared_keys,
                    party_id,
                    vss_scheme_vec,
                    paillier_key_vec,
                    master_public_key,
                };

                match ecdsa_params.validate() {
                    Ok(_valid) => Ok(ecdsa_params),
                    Err(e) => Err(e),
                }
            },
            Err(error) => Err(error.to_string()),
        }
    }

    /// Read ECDSA parameters from a key file.
    ///
    /// Supports two formats:
    /// - **Standalone**: the file contains raw ECDSA key data (a JSON array).
    /// - **Combined**: the file contains `{"ecdsa": <data>, "eddsa": <data>}` and
    ///   the ECDSA portion is extracted automatically.
    pub fn read_from_file(keys_file_path: String) -> Result<ECDSAParameters, String> {
        let data = fs::read_to_string(keys_file_path.clone())
            .map_err(|err| format!("Location: {}, Error: {:?}", keys_file_path, err))?;

        // Try combined format first: {"ecdsa": ..., "eddsa": ...}
        if let Ok(combined) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(ecdsa_value) = combined.get("ecdsa") {
                let ecdsa_str = ecdsa_value.to_string();
                return Self::read_from_string(&ecdsa_str);
            }
        }

        // Fall back to standalone format
        Self::read_from_string(&data)
    }

    pub fn validate(&self) -> Result<bool, String> {
        if self.party_key.y_i.is_zero() {
            return Err(PUBLIC_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_key.u_i.is_zero() {
            return Err(PRIVATE_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_key.dk.p.is_zero() || self.party_key.dk.q.is_zero() {
            return Err("Invalid decryption key in party_key".to_string());
        }

        if self.party_key.ek.n.is_zero() || self.party_key.ek.nn.is_zero() {
            return Err("Invalid encryption key in party_key".to_string());
        }

        if self.party_key.party_index == 0 {
            return Err(PARTY_INDEX_ERROR_IN_FILE.to_string());
        }

        if self.chain_code.is_zero() {
            return Err(CHAIN_CODE_ERROR_IN_FILE.to_string());
        }

        if self.shared_keys.y.is_zero()
            || self.shared_keys.x_i.is_zero() {
            return Err(SHARED_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_id == 0 {
            return Err(PARTY_ID_ERROR_IN_FILE.to_string());
        }

        if self.master_public_key.is_zero() {
            return Err(INVALID_MASTER_PUBLIC_KEY_IN_FILE.to_string());
        }

        // Validate vss_scheme_vec: A vector of vectors of GE elements
        validate_vss_scheme_vector(self.vss_scheme_vec.clone())
    }
}


pub fn run_pubkey_or_sign(
    action:&str,
    keysfile_path:&str,
    path:&str,
    message_str:&str,
    manager_addr:String,
    params:Vec<&str>,
    hd_variant: HdImplementation,
) -> Result<Value, String>
{
    // Read data from keys file
    let ECDSAParameters {
        party_key,
        chain_code,
        shared_keys,
        party_id,
        mut vss_scheme_vec,
        paillier_key_vec,
        master_public_key: y_sum
    } = ECDSAParameters::read_from_file (keysfile_path.to_string())
        .map_err(|error| format!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error))?;

    // Get root pub key or HD pub key at specified path
    let (derived_child, tweak, derived_chain_code) = match path.is_empty() {
        true => (y_sum, Scalar::<Secp256k1>::zero(), chain_code.to_bytes().to_vec()),
        false => match hd_variant{
            HdImplementation::Legacy => {
                let chain_code_point= GE::generator() * chain_code.clone();
                hd_keys::get_legacy_hd_key(&y_sum, path, chain_code_point)
            }
            HdImplementation::Bip32 => {
                let chain_code_bytes = chain_code.to_bytes().to_vec();
                let (derived_child, tweak, derived_chain_code)
                    = match path.contains('\'') {
                        false => hd_keys::get_hd_child_by_crate(y_sum, path, chain_code_bytes),
                        true => hd_keys::get_hardened_hd_child_by_crate(
                            party_key.u_i.clone(),
                            path,
                            chain_code_bytes
                        )
                    };
                let tweak_scaler = FE::from_bytes(tweak.as_slice()).unwrap();
                (derived_child, tweak_scaler, derived_chain_code)
            }
        }
    };

    // Return pub key as x,y
    let result = if action == "pubkey" {
        let ret_dict = json!({
                    "x": hex::encode(derived_child.x_coord().unwrap().to_bytes().to_vec()),
                    "y": hex::encode(derived_child.y_coord().unwrap().to_bytes().to_vec()),
                    "path": path,
                    "chain_code": hex::encode(derived_chain_code),
                    //"tweak": hex::encode(tweak.to_bytes().to_vec()),
                });
        ret_dict
    }
    else {

        if !validate_hex_string(message_str) {
            return Err(format!("{}", INVALID_MESSAGE_STRING_ERROR));
        }

        // Parse message to sign
        let message = match hex::decode(message_str) {
            Ok(x) => x,
            Err(_e) => message_str.as_bytes().to_vec(),
        };
        let message = &message[..];

        //            println!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
        let params = Params {
            threshold: params[0].to_string(),
            parties: params[1].to_string(),
        };
        signer::sign(
            manager_addr,
            party_key,
            shared_keys,
            party_id,
            &mut vss_scheme_vec,
            paillier_key_vec,
            &derived_child,
            &params,
            &message,
            &tweak,
            !path.is_empty(),
        )?
    };

    Ok(result)
}

pub(crate) fn check_key_file(keysfile_path:&str, limit: usize) -> Result<bool, String> {
    // Read data from keys file
    match ECDSAParameters::read_from_file (keysfile_path.to_string()) {
        Ok(params) => {
            println!("max_first primes is set to: {:?}", limit);

            let mut failed = false;
            println!("Checking paillier_key_vector[..].n");
            for paillier_key in params.paillier_key_vec.iter() {
                if is_divisible_by_first_n_primes(paillier_key.n.clone(), limit) {
                    failed = true;
                };
            }

            Ok(failed)
        }
        Err(error) => {
            Err(format!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error))
        }
    }
}

pub(crate) fn sum_of_fragment_files(keyfiles: Vec<String>) -> Result<(GE, GE, FE), String> {
    let mut sum_u_s = Scalar::<Secp256k1>::zero();
    let mut master_y = Point::<Secp256k1>::zero();
    for key_file_path in keyfiles.iter() {
        let ECDSAParameters {
            party_key: party_keys,
            chain_code: _,
            shared_keys: _,
            party_id: _,
            vss_scheme_vec: _,
            paillier_key_vec: _,
            master_public_key: Y
        } = match ECDSAParameters::read_from_file(key_file_path.clone()) {
            Ok(x) => x,
            Err(error) => {
                eprintln!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error);
                return Err(error);
            }
        };
        sum_u_s = sum_u_s + party_keys.u_i;
        master_y = Y;
    }
    // sum_u_s is actually the master private key:
    let summation_pub_key = sum_u_s.clone() * Point::generator();
    Ok((summation_pub_key, master_y, sum_u_s))
}