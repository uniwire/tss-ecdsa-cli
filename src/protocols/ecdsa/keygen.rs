use std::time;
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    BigInt,
};
use curv::elliptic::curves::{Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use sha2::{Sha256};

use crate::common::{
    aes_decrypt,
    aes_encrypt,
    poll_for_p2p,
    sendp2p,
    Params,
    AEAD,
    Client,
    keygen_signup,
    is_divisible_by_first_n_primes,
    MAX_FIRST_PRIMES
};
use crate::protocols::{generate_shared_chain_code};
use crate::ecdsa::{CURVE_NAME, FE, GE};


pub fn run_keygen(addr: &String, params: &Vec<&str>, room_id: String) -> Result<String, String> {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();

    let client = Client::new(addr.to_string());

    // delay:
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let tn_params = Params {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };

    eprintln!("{{\"event\":\"waiting\",\"parties\":{}}}", PARTIES);
    let (party_num_int, uuid) = match keygen_signup(&client, tn_params, CURVE_NAME, room_id) {
        Ok((party_num_int, uuid)) => {
            eprintln!("{{\"event\":\"registered\",\"party\":{},\"parties\":{}}}", party_num_int, PARTIES);
            (party_num_int, uuid)
        }
        Err(error) => {
            return Err(format!("Signup for keygen failed: {}", error));
        }
    };

    let party_keys = Keys::create_safe_prime(party_num_int);

    let chain_code = generate_shared_chain_code::<Secp256k1, Sha256>(
        client.clone(),
        party_num_int,
        PARTIES,
        uuid.clone(),
        delay,
        params.share_count as usize
    )?;

    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    let pailiar_key_for_checking = bc_i.clone();
    if is_divisible_by_first_n_primes(pailiar_key_for_checking.e.n, MAX_FIRST_PRIMES) {
        return Err("Error: unsafe pailiar key found! Try to run the script again.".to_string());
    }

    // send commitment to ephemeral public keys, get round 1's commitments of other parties
    let round1_ans_vec = client.exchange_data(
        party_num_int,
        PARTIES,
        uuid.clone(),
        "round1",
        delay,
        serde_json::to_string(&bc_i).unwrap(),
    )?;

    eprintln!("{{\"event\":\"signup\",\"party\":{},\"parties\":{}}}", party_num_int, PARTIES);

    let bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    // send ephemeral public keys and check commitments correctness
    let round2_ans_vec = client.exchange_data(
        party_num_int,
        PARTIES,
        uuid.clone(),
        "round2",
        delay,
        serde_json::to_string(&decom_i).unwrap(),
    )?;

    let mut point_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for j in 1..=PARTIES {
        let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[(j -1) as usize]).unwrap();
        point_vec.push(decom_j.clone().y_i);
        decom_vec.push(decom_j.clone());
        if j != party_num_int {
            enc_keys.push((decom_j.clone().y_i * party_keys.clone().u_i).x_coord().unwrap());
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////
    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext)
                .map_err(|e| format!("Encryption error: {}", e))? ;

            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone(),
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round3",
        uuid.clone(),
    )?;

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            match aes_decrypt(&key_i, aead_pack) {
                Ok(out) => {
                    let out_bn = BigInt::from_bytes(&out);
                    let out_fe = Scalar::<Secp256k1>::from(&out_bn);
                    party_shares.push(out_fe);

                    j += 1;
                }
                Err(error) => {
                    return Err(format!("Decryption error: {}", error));
                }
            }
        }
    }

    // round 4: send vss commitments
    let round4_ans_vec = client.exchange_data(
        party_num_int,
        PARTIES,
        uuid.clone(),
        "round4",
        delay,
        serde_json::to_string(&vss_scheme).unwrap(),
    )?;

    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    for j in 0..PARTIES as usize {
        let vss_scheme_j: VerifiableSS<Secp256k1> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
        vss_scheme_vec.push(vss_scheme_j);
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    let round5_ans_vec = client.exchange_data(
        party_num_int,
        PARTIES,
        uuid.clone(),
        "round5",
        delay,
        serde_json::to_string(&dlog_proof).unwrap(),
    )?;

    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = Vec::new();
    for j in 0..PARTIES as usize {
        let dlog_proof_j: DLogProof<Secp256k1, Sha256> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
        dlog_proof_vec.push(dlog_proof_j);
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        chain_code,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();
    eprintln!("{{\"event\":\"complete\"}}");
    Ok(keygen_json)
}
