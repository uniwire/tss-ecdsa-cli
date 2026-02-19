use std::time;
use std::string::String;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519};
use multi_party_eddsa::protocols::thresholdsig::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters};
use sha2::Sha512;

use crate::common::{
    AEAD,
    aes_decrypt,
    aes_encrypt,
    AES_KEY_BYTES_LEN,
    Client,
    keygen_signup,
    Params,
    poll_for_p2p,
    sendp2p
};
use crate::protocols::{generate_shared_chain_code, verify_dlog_proofs};
use crate::eddsa::{CURVE_NAME, FE, GE};


pub fn run_keygen(addr: &String, params: &Vec<&str>, room_id: String) -> Result<String, String> {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();
    let client = Client::new(addr.clone());

    // delay:
    let delay = time::Duration::from_millis(25);
    let parameters = Parameters {
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

    let party_keys = Keys::phase1_create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast();

    let chain_code = generate_shared_chain_code::<Ed25519, Sha512>(
        client.clone(),
        party_num_int,
        PARTIES,
        uuid.clone(),
        delay,
        parameters.share_count as usize
    )?;

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
    let mut blind_vec: Vec<BigInt> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for j in 1..=PARTIES as usize {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str::<KeyGenDecommitMessage1>(
                &round2_ans_vec[j -1]
            ).unwrap();
            point_vec.push(decom_j.clone().y_i);
            blind_vec.push(decom_j.clone().blind_factor);
        if j != party_num_int as usize {
            let key_bn: BigInt = (decom_j.y_i * party_keys.keypair.expanded_private_key.private_key.clone()).x_coord().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let key_gen_parties_points_vec = (0..PARTIES)
        .map(|i| i + 1)
        .collect::<Vec<u16>>();

    let (vss_scheme, secret_shares) = party_keys
        .phase1_verify_com_phase2_distribute(
            &parameters, &blind_vec, &point_vec, &bc1_vec, &key_gen_parties_points_vec
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////
    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext)
                .map_err(|e| format!("Encryption error: {}", e))?;
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            ).is_ok());
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
            let key_i = &enc_keys[j];
            match aes_decrypt(key_i, aead_pack) {
                Ok(out) => {
                    let out_bn = BigInt::from_bytes(&out[..]);
                    let out_fe = FE::from(&out_bn);
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
    let mut vss_scheme_vec: Vec<VerifiableSS<Ed25519>> = Vec::new();
    for j in 0..PARTIES as usize {
        let vss_scheme_j: VerifiableSS<Ed25519> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
        vss_scheme_vec.push(vss_scheme_j);
    }

    let shared_keys = party_keys
        .phase2_verify_vss_construct_keypair(
            &parameters,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    let dlog_proof: DLogProof<Ed25519, Sha512> = DLogProof::prove(&shared_keys.x_i);

    // round 5: send dlog proof
    let round5_ans_vec = client.exchange_data(
        party_num_int,
        PARTIES,
        uuid.clone(),
        "round5",
        delay,
        serde_json::to_string(&dlog_proof).unwrap(),
    )?;
    let mut dlog_proof_vec: Vec<DLogProof<Ed25519, Sha512>> = Vec::new();
    for j in 0..PARTIES as usize {
        let dlog_proof_j: DLogProof<Ed25519, Sha512> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
        dlog_proof_vec.push(dlog_proof_j);
    }

    verify_dlog_proofs(
        parameters.share_count as usize,
        &dlog_proof_vec,
        point_vec.len(),
    ).expect("bad dlog proof");

    let keygen_json = serde_json::to_string(&(
        party_keys,
        chain_code,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        y_sum,
    )).unwrap();
    eprintln!("{{\"event\":\"complete\"}}");
    Ok(keygen_json)
}