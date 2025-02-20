use std::str::{from_utf8};

use risc0_zkvm::guest::env;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha256};
use bitcoin::{Transaction, BlockHash, XOnlyPublicKey};
use k256::PublicKey;
use k256::SecretKey;

use shared::{get_leaf_hashes, new_p2tr, tweak_pubkey};


fn main() {
    //TODO: take in nodeid1, nodeid2, bitcoinkey1, bitcoinkey2 need tweak?
    // check combining bitcoin keys give a key that is in the UTXO set.
    // combine all 4 keys and check that the signature is valid for the aggregate key
    // How to avoid proof reuse? cannot do hash of priv key easily, since there are two nodes maybe
    // do hash of the individual public keys? since they won't ever go onchain


    // read the input
    let s: Stump = env::read();
    let proof: Proof = env::read();

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

    // We'll check that the given public key corresponds to an output in the utxo set.
    let script_pubkey = new_p2tr(tap_pub, None);

    // assert internal key is in tx used to calc leaf hash
    assert_eq!(tx.output[vout as usize].script_pubkey, script_pubkey);

    let lh = get_leaf_hashes(&tx, vout, block_height, block_hash);
    let leaf_hash = NodeHash::from(lh);

    // Assert it is in the set.
    assert_eq!(s.verify(&proof, &[leaf_hash]), Ok(true));

    let mut shasher = Sha256::new();
    s.serialize(&mut shasher).unwrap();
    let stump_hash = hex::encode(shasher.finalize());

    // write public output to the journal
    env::commit(&p_out);
    env::commit(&stump_hash);
}