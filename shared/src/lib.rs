use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash as BitcoinHash;

use sha2::{Digest, Sha512_256};

use bitcoin::consensus::Encodable;
use bitcoin::key::Keypair;
use bitcoin::{BlockHash, Transaction};
use k256::PublicKey;

use musig2::{
    k256, AggNonce, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecNonce,
    SecNonceSpices, SecondRound,
};

pub const UTREEXO_TAG_V1: [u8; 64] = [
    0x5b, 0x83, 0x2d, 0xb8, 0xca, 0x26, 0xc2, 0x5b, 0xe1, 0xc5, 0x42, 0xd6, 0xcc, 0xed, 0xdd, 0xa8,
    0xc1, 0x45, 0x61, 0x5c, 0xff, 0x5c, 0x35, 0x72, 0x7f, 0xb3, 0x46, 0x26, 0x10, 0x80, 0x7e, 0x20,
    0xae, 0x53, 0x4d, 0xc3, 0xf6, 0x42, 0x99, 0x19, 0x99, 0x31, 0x77, 0x2e, 0x03, 0x78, 0x7d, 0x18,
    0x15, 0x6e, 0xb3, 0x15, 0x1e, 0x0e, 0xd1, 0xb3, 0x09, 0x8b, 0xdc, 0x84, 0x45, 0x86, 0x18, 0x85,
];

pub fn get_leaf_hashes(
    transaction: &Transaction,
    vout: u32,
    height: u32,
    block_hash: BlockHash,
) -> sha256::Hash {
    let header_code = height << 1;

    let mut ser_utxo = Vec::new();
    let utxo = transaction.output.get(vout as usize).unwrap();
    utxo.consensus_encode(&mut ser_utxo).unwrap();
    let header_code = if transaction.is_coinbase() {
        header_code | 1
    } else {
        header_code
    };
    let txid = transaction.compute_txid();
    println!("txid: {txid}, block_hash: {block_hash} vout: {vout} height: {height}");

    let leaf_hash = Sha512_256::new()
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(block_hash)
        .chain_update(txid)
        .chain_update(vout.to_le_bytes())
        .chain_update(header_code.to_le_bytes())
        .chain_update(ser_utxo)
        .finalize();
    sha256::Hash::from_slice(leaf_hash.as_slice()).expect("parent_hash: Engines shouldn't be Err")
}

pub fn aggregate_keys(pubs: Vec<PublicKey>) -> PublicKey {
    let key_agg_ctx = KeyAggContext::new(pubs.clone()).unwrap();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

    aggregated_pubkey
}

pub fn verify_musig(pubs: Vec<PublicKey>, sig: [u8; 64], message: &Vec<u8>) -> bool {
    let aggregated_pubkey: PublicKey = aggregate_keys(pubs);

    musig2::verify_single(aggregated_pubkey, &sig, message)
        .expect("aggregated signature must be valid");

    true
}

pub fn sort_pubkeys(pubkeys: &mut Vec<PublicKey>) {
    pubkeys.sort_by(|a, b| a.to_sec1_bytes().cmp(&b.to_sec1_bytes()));
}

pub fn sort_keypairs(kp: &mut Vec<Keypair>) {
    kp.sort_by(|a, b| a.public_key().serialize().cmp(&b.public_key().serialize()));
}
