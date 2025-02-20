use std::str::{from_utf8};

use risc0_zkvm::guest::env;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha256};
use bitcoin::{Transaction, BlockHash, XOnlyPublicKey};
use k256::PublicKey;
use k256::SecretKey;

use shared::{get_leaf_hashes, verify_musig, aggregate_keys, sort_pubkeys, new_p2tr, tweak_pubkey};


fn main() {
    //TODO: take in nodeid1, nodeid2, bitcoinkey1, bitcoinkey2 need tweak?
    // check combining bitcoin keys give a key that is in the UTXO set.
    // combine all 4 keys and check that the signature is valid for the aggregate key
    // How to avoid proof reuse? cannot do hash of priv key easily, since there are two nodes maybe
    // do hash of the individual public keys? since they won't ever go onchain


    // read the input
//    let msg_bytes: Vec<u8> = env::read();
    let s: Stump = env::read();
    let proof: Proof = env::read();

    //let lh : [u8; 32] = env::read();
    let tx: Transaction = env::read();
    let vout: u32 = env::read();
    let block_height: u32 = env::read();
    let block_hash: BlockHash = env::read();

    // P + blinding key
    let p_out: PublicKey = env::read();
    let blind_secret_bytes: [u8; 32] = env::read();
    eprintln!("blind_secret_bytes: {}", hex::encode(blind_secret_bytes));

    // Blinding beta = h(r || P)
    let beta: [u8; 32] = Sha256::new()
        .chain_update(blind_secret_bytes)
        .chain_update(p_out.to_sec1_bytes())
        .finalize()
        .try_into()
        .unwrap();

    let tap_point = tweak_pubkey(p_out, &beta);
    let tap_pub: PublicKey = tap_point.try_into().unwrap();
    eprintln!("tap blind key : {}", hex::encode(&tap_pub.to_sec1_bytes()));
   // let musig_sig_bytes: Vec<u8> = env::read();

//    let mut musig_pubs = all_pubs.clone();
//    sort_pubkeys(&mut musig_pubs);
//
//    assert_eq!(
//        verify_musig(musig_pubs.clone(), musig_sig_bytes.clone().try_into().unwrap(), &msg_bytes),
//        true,
//    );
//
//    let node_key1 = all_pubs[0];
//    let node_key2 = all_pubs[1];
//
//    // Aggregate the bitcoin keys.
//    let bitcoin_key1 = all_pubs[2];
//    let bitcoin_key2 = all_pubs[3];
//    let mut bitcoin_keys =vec![bitcoin_key1, bitcoin_key2];
//    sort_pubkeys(&mut bitcoin_keys);
//    let tap_pub = aggregate_keys(bitcoin_keys);

    let lh = get_leaf_hashes(&tx, vout, block_height, block_hash);
    let leaf_hash = NodeHash::from(lh);

    // We'll check that the given public key corresponds to an output in the utxo set.
    let script_pubkey = new_p2tr(tap_pub, None);

    // assert internal key is in tx used to calc leaf hash
    assert_eq!(tx.output[vout as usize].script_pubkey, script_pubkey);

    // Assert it is in the set.
    assert_eq!(s.verify(&proof, &[leaf_hash]), Ok(true));

    //let mut hasher = Sha512_256::new();
    //hasher.update(&bitcoin_key1.to_sec1_bytes());
    //hasher.update(&bitcoin_key2.to_sec1_bytes());
    //let pk_hash = hex::encode(hasher.finalize());

    let mut shasher = Sha256::new();
    s.serialize(&mut shasher).unwrap();
    let stump_hash = hex::encode(shasher.finalize());

    // write public output to the journal
    env::commit(&p_out);
    //env::commit(&node_key2);
    env::commit(&stump_hash);
    //env::commit(&pk_hash);
    //env::commit(&msg_bytes);
}