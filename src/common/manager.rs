use std::collections::HashMap;
use std::env;
use std::process::exit;
use std::sync::RwLock;
use std::time::Duration;
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation, decode_header};
use rocket::{Ignite, post, Rocket, routes, State, async_trait, Request, Build, Error};
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};

use ttlhashmap::TtlHashMap;

use uuid::Uuid;

use crate::common::{
    error_message,
    JwtClaims,
    Entry,
    Index,
    Key,
    ManagerError,
    PartySignup,
    PartySignupRequestBody,
    SigningPartySignup,
    KeygenSignupRequestBody
};
use crate::common::signing_room::SigningRoom;

const TSS_CLI_MANAGER_TTL_VAR: &str = "TSS_CLI_MANAGER_TTL";
const TSS_CLI_MANAGER_TTL_DEFAULT: &str = "300";
const MANAGER_MAX_PARTIES_VAR: &str = "TSS_MANAGER_MAX_PARTIES";
const MANAGER_MAX_PARTIES_DEFAULT: u16 = 10;
const HTTP_AUTH_KEY_PAIRS_VAR: &str = "TSS_MANAGER_HTTP_AUTH_KEY_PAIRS";
const LOCKING_ERROR_MESSAGE: &str = "Could not acquire lock!";
// Define the ApiKey struct, which will be extracted from the JWT token
pub struct ApiKeyJwt {
    api_key: String
}

// Implementing FromRequest for ApiKey to validate JWT
#[async_trait]
impl<'r> FromRequest<'r> for ApiKeyJwt {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let user_secret_keys_result = request.rocket().state::<Result<HashMap<String, String>, bool>>()
            .expect("User secret keys not found");

        match user_secret_keys_result {
            Err(authentication_disabled) => {
                if *authentication_disabled {
                    Outcome::Success(ApiKeyJwt{ api_key: "anonymous".to_string()})
                }
                else {
                    Outcome::Error((Status::Unauthorized, "User credentials are not set properly by admins".to_string()))
                }
            },
            Ok(user_secret_keys) => {
                // Get the Authorization header
                if let Some(auth_header) = request.headers().get_one("Authorization") {
                    // The Authorization header will be of the form "Bearer <token>"
                    if let Some(token) = auth_header.strip_prefix("Bearer ") {
                        match validate_jwt(token, user_secret_keys) {
                            Ok(token_data) => {
                                // If JWT is valid, return the ApiKey
                                Outcome::Success(ApiKeyJwt{ api_key: token_data.claims.api_key })
                            }
                            Err(_) => {
                                // If JWT is invalid, return Unauthorized
                                Outcome::Error((Status::Unauthorized, "Invalid or expired token".to_string()))
                            }
                        }
                    } else {
                        Outcome::Error((Status::Unauthorized, "Authorization header must start with Bearer".to_string()))
                    }
                } else {
                    Outcome::Error((Status::Unauthorized, "Authorization header missing".to_string()))
                }
            }
        }
    }
}


// Function to validate the JWT
fn validate_jwt(token: &str, user_secrets: &HashMap<String, String>) -> JwtResult<TokenData<JwtClaims>> { //JwtResult<Claims>
    // Step 1: Decode the JWT to extract the claims
    match decode_header(token) {
        Ok(token_data) => {
            // Step 2: Get the API key from the decoded claims (kid)
            match token_data.kid {
                Some(api_key) => {
                    // Step 3: Look up the secret key for that user (given api_key)
                    if let Some(user_secret) = user_secrets.get(&api_key) {
                        // Step 4: Validate the JWT using the user's secret key
                        let decoding_key = DecodingKey::from_secret(user_secret.as_bytes());
                        let validation = Validation::new(Algorithm::HS256);
                        decode::<JwtClaims>(token, &decoding_key, &validation)
                    } else {
                        Err(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))
                    }
                }
                None => {
                    Err(jsonwebtoken::errors::Error::from(
                        ErrorKind::MissingRequiredClaim("Api key is missing".to_string())
                    ))
                }

            }
        }
        Err(err) => {
            Err(err)
        }
    }
}

fn parse_user_secrets_from_env() -> Result<HashMap<String, String>, bool> {
    let mut user_secret_keys = HashMap::new();
    // Read the environment variable
    if let Ok(secret_string) = env::var(HTTP_AUTH_KEY_PAIRS_VAR) {
        // Parse the secret string, assuming a format like "user123=secretkey123,user456=secretkey456"
        for pair in secret_string.split(',') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(api_key), Some(secret)) = (parts.next(), parts.next()) {
                user_secret_keys.insert(api_key.to_string(), secret.to_string());
            }
        }
    } else {
        eprintln!("\x1b[0;33m{} environment variable is not set. Authentication deactivated.\x1b[0m", HTTP_AUTH_KEY_PAIRS_VAR);
        return Err(true); // true means authentication is disabled by admin intentionally
    }

    Ok(user_secret_keys)
}


fn validate_t_n_params(num_parties: u16, threshold: u16) -> Result<bool, String> {
    let max_allowed_parties = env::var(MANAGER_MAX_PARTIES_VAR)
        .ok()
        .and_then(|max_n| max_n.parse::<u16>().ok())
        .unwrap_or(MANAGER_MAX_PARTIES_DEFAULT);
    if threshold < 1 {
        Err(format!("Invalid threshold (t) is given: {}. It must be grater than 1.", threshold).to_string())
    }
    else if num_parties <= threshold {
        Err(format!("The threshold (t) must be lower than total parties {}, passed: {}",
                    num_parties, threshold).to_string()
        )
    }
    else if num_parties > max_allowed_parties {
        Err(format!("Maximum {} parties limit reached. Increase param {} on manager to allow more.",
                    MANAGER_MAX_PARTIES_DEFAULT, MANAGER_MAX_PARTIES_VAR).to_string()
        )
    }
    else {
        Ok(true)
    }
}

#[rocket::main]
pub async fn run_manager() -> Result<Rocket<Ignite>, Error> {
    match build_manager() {
        Ok(manager) => {
            manager.launch().await
        }
        Err(error) => Err(error),
    }
}

pub fn build_manager() -> Result<Rocket<Build>, Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let ttl_result = env::var(TSS_CLI_MANAGER_TTL_VAR)
        .unwrap_or(TSS_CLI_MANAGER_TTL_DEFAULT.to_string()).parse::<u64>();
    match ttl_result {
        Ok(ttl) => {
            let db: TtlHashMap<Key, String> = TtlHashMap::new(Duration::from_secs(ttl));
            let db_mtx = RwLock::new(db);

            let user_secret_keys: Result<HashMap<String, String>, bool> = parse_user_secrets_from_env();

            Ok(rocket::build()
                .mount("/", routes![get, set, signup_keygen, signup_sign])
                .manage(db_mtx)
                .manage(user_secret_keys))
        }
        Err(error) => {
            eprintln!("Error in parsing env var: {}, {}. It must be an integer.", TSS_CLI_MANAGER_TTL_VAR, error);
            exit(1);
        }
    }
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<Index>,
    jwt_guard: ApiKeyJwt
) -> Json<Result<Entry, ManagerError>> {
    let index: Index = request.0;
    match db_mtx.write() {
        Ok(mut hm) => {
            match hm.get(&index.key) {
                Some(v) => {
                    let entry = Entry {
                        key: index.key,
                        value: v.clone().to_string(),
                    };
                    Json(Ok(entry))
                }
                None => {
                    Json(Err(ManagerError{
                        error: error_message("Invalid request!",
                                             format!("Key not found: {}", index.key.as_str()).as_str()
                        )
                    }))
                },
            }
        }
        Err(error) => {
            Json(Err(ManagerError{error: error_message(LOCKING_ERROR_MESSAGE, &error.to_string())}))
        }
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
       request: Json<Entry>,
       jwt_guard: ApiKeyJwt
) -> Json<Result<(), ManagerError>> {
    let entry: Entry = request.0;
    match db_mtx.write() {
        Ok(mut hm) => {
            hm.insert(entry.key.clone(), entry.value.clone());
            Json(Ok(()))
        }
        Err(error) => {
            Json(Err(ManagerError{error: error_message(LOCKING_ERROR_MESSAGE, &error.to_string())}))
        }
    }

}

#[post("/signupkeygen", format = "json", data = "<request>")]
fn signup_keygen(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<KeygenSignupRequestBody>,
    jwt_guard: ApiKeyJwt
) -> Json<Result<PartySignup, ManagerError>> {
    println!("Got a signup request for keygen from: {:?}", jwt_guard.api_key);

    let room_id = request.room_id.clone();

    let parties = match request.params.parties.parse::<u16>() {
        Ok(parties) => parties,
        Err(error) => {
            return Json(Err(ManagerError{
                error: error_message("Could not parse parties!", &error.to_string())
            }))
        }
    };
    let threshold = match request.params.threshold.parse::<u16>() {
        Ok(threshold) => {threshold}
        Err(error) => {
            return Json(Err(ManagerError{
                error: error_message("Could not parse parameters!", &error.to_string())
            }))
        }
    };
    match validate_t_n_params(parties, threshold) {
        Ok(_valid) => {},
        Err(message) => return Json(Err(ManagerError {error: message.to_string()}))
    }
    let curve = &match request.curve_name.parse::<String>() {
        Ok(curve) => {curve}
        Err(error) => {
            return Json(Err(ManagerError{error: error.to_string()}))
        }
    };
    let mut key = "signup-keygen-".to_string() + curve;
    key.push_str(room_id.as_str());

    match db_mtx.write() {
        Ok(mut hm) => {
            let client_signup = match hm.get(&key) {
                Some(json_string) => {
                    match serde_json::from_str(json_string) {
                        Ok(signup) => signup,
                        Err(_error) => {
                            return Json(Err(ManagerError{
                                error: "Could not json decode the value stored in hash map!".to_string()
                            }))
                        }
                    }
                },
                None => PartySignup {
                    number: 0,
                    uuid: Uuid::new_v4().to_string(),
                },
            };

            let party_signup = {
                if client_signup.number < parties {
                    PartySignup {
                        number: client_signup.number + 1,
                        uuid: client_signup.uuid,
                    }
                } else {
                    PartySignup {
                        number: 1,
                        uuid: Uuid::new_v4().to_string(),
                    }
                }
            };
            match serde_json::to_string(&party_signup) {
                Ok(encoded_party_signup) => {
                    hm.insert(key, encoded_party_signup);
                    Json(Ok(party_signup))
                }
                Err(_error) => {
                    Json(Err(ManagerError{
                        error: "Could not json encode the party signup!".to_string()
                    }))
                }
            }
        }
        Err(error) => {
            Json(Err(ManagerError{error: error_message(LOCKING_ERROR_MESSAGE, &error.to_string())}))
        }
    }
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<PartySignupRequestBody>,
    jwt_guard: ApiKeyJwt
) -> Json<Result<SigningPartySignup, ManagerError>> {
//     println!("Got a signup request for sign from: {:?}", jwt_guard.api_key);

    let threshold = request.clone().threshold;
    let room_id = request.room_id.clone();
    let party_uuid = request.party_uuid.clone();
    let new_signup_request = party_uuid.is_empty();
    let party_number = request.party_number;
    // In signing we don't get the "n" parameter from parties, thus we assume n=t+1 :
    match validate_t_n_params(threshold+1, threshold) {
        Ok(_valid) => {},
        Err(message) => return Json(Err(ManagerError {error: message.to_string()}))
    }
    let mut key = "signup-sign-".to_owned() + &request.curve_name;
    key.push_str(&room_id);

    let mut hm = match db_mtx.write(){
        Ok(hm) => hm,
        Err(error) => {
            return Json(Err(ManagerError{
                error: error_message(LOCKING_ERROR_MESSAGE, &error.to_string())
            }))
        }
    };

    let mut signing_room = match hm.get(&key) {
        Some(o) => {
            match serde_json::from_str(o) {
                Ok(signing_room) => signing_room,
                Err(_error) => {
                    return Json(Err(ManagerError{
                        error: "Could not decode the signing room!".to_string()
                    }))
                }
            }
        },
        None => SigningRoom::new(room_id.clone(), threshold+1),
    };

    if signing_room.last_stage != "signup" {
        if signing_room.has_member(party_number, party_uuid.clone()) {
            return Json(signing_room.get_signup_info(party_number));
        }

        if signing_room.are_all_members_inactive() {
            let debug = format!("message: All parties have been inactive. Renewed the room. \
                room_id: {}, \
                fragment.index: {}", room_id, party_number);
            println!("{}", debug);
            signing_room = SigningRoom::new(room_id, threshold + 1)
        }
        else {
            return Json(Err(ManagerError{
                error: "Room signup phase is terminated".to_string()
            }));
        }
    }

    if signing_room.is_full() && signing_room.are_all_members_active() && new_signup_request {
        return Json(Err(ManagerError{
            error: "Room is full, all members active".to_string()
        }));
    }

    let party_signup_result = {
        if !new_signup_request {
            if !signing_room.has_member(party_number, party_uuid) {
                return Json(Err(ManagerError{
                    error: "No party found with the given uuid, probably replaced due to timeout".to_string()
                }));
            }
            //if signing_room.is_member_active(party_number) {
            signing_room.update_ping(party_number)
            //}
            //Else is handled in the next block
        } else if signing_room.member_info.contains_key(&party_number) {
            match signing_room.is_member_active(party_number) {
                Ok(is_active) => {
                    if is_active {
                        return Json(Err(ManagerError{
                            error: "Received a re-signup request for an active party. Request ignored".to_string()
                        }));
                    }
                    println!("Received a re-signup request for a timed-out party {:?}, thus UUID is renewed", party_number);
                    signing_room.replace_party(party_number)
                }
                Err(error) => {Err(error)}
            }
        }
        else {
            match signing_room.add_party(party_number) {
                Ok(party_signup) => Ok(party_signup),
                Err(message) => return Json(Err(ManagerError{error: message.to_string()}))
            }
        }
    };

    match party_signup_result {
        Ok(party_signup) => {
            match serde_json::to_string(&signing_room) {
                Ok(signing_room_json) => {
                    hm.insert(key.clone(), signing_room_json);
                    Json(Ok(party_signup))
                }
                Err(error) => {Json(Err(ManagerError{error: error.to_string()}))}
            }
        },
        Err(error) => Json(Err(error))
    }
}
