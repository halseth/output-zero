use bitcoin_hashes::HashEngine;
use bitcoin_hashes::Hash as BitcoinHash;

use sha2::{Digest, Sha256 };

use bitcoin::consensus::Encodable;
use bitcoin::key::{
    Keypair, Parity, Secp256k1, TweakedPublicKey, UntweakedPublicKey, Verification,
};
use bitcoin::script::{Builder, PushBytes};
use bitcoin::{
    BlockHash, ScriptBuf, TapNodeHash, TapTweakHash, Transaction, Txid, WitnessVersion,
    XOnlyPublicKey,
};
use k256::PublicKey;
use k256::ProjectivePoint;

use musig2::k256::elliptic_curve::point::AffineCoordinates;
use musig2::k256::elliptic_curve::sec1::ToEncodedPoint;
use musig2::{k256, KeyAggContext};

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
) -> [u8; 32] {
    let header_code = height << 1;

    let mut ser_utxo = Vec::new();
    let utxo = transaction.output.get(vout as usize).unwrap();
    utxo.consensus_encode(&mut ser_utxo).unwrap();
    let header_code = if transaction.is_coinbase() {
        header_code | 1
    } else {
        header_code
    };
    let txid = compute_txid(&transaction);
    println!("txid: {txid}, block_hash: {block_hash} vout: {vout} height: {height}");

    let leaf_hash = Sha256::new()
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(block_hash)
        .chain_update(txid)
        .chain_update(vout.to_le_bytes())
        .chain_update(header_code.to_le_bytes())
        .chain_update(ser_utxo)
        .finalize();
    leaf_hash.try_into().unwrap()
}

pub fn compute_txid(tx: &Transaction) -> Txid {
    let mut enc = Vec::new();
    tx.version.consensus_encode(&mut enc).expect("engines don't error");
    tx.input.consensus_encode(&mut enc).expect("engines don't error");
    tx.output.consensus_encode(&mut enc).expect("engines don't error");
    tx.lock_time.consensus_encode(&mut enc).expect("engines don't error");

    // Compute double SHA-256 hash
    let hash_result = Sha256::digest(Sha256::digest(&enc));

    // Convert the hash result to a Txid
    Txid::from_slice(&hash_result).expect("hash should be valid Txid")
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
pub fn new_p2tr(internal_key: PublicKey, merkle_root: Option<TapNodeHash>) -> ScriptBuf {
    let output_key = tap_tweak(internal_key, merkle_root);
    // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
    new_witness_program_unchecked(WitnessVersion::V1, output_key)
}

fn new_witness_program_unchecked<T: AsRef<PushBytes>>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In segwit v0, the program must be 20 or 32 bytes long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new()
        .push_opcode(version.into())
        .push_slice(program)
        .into_script()
}

pub fn secp_new_p2tr<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: UntweakedPublicKey,
    merkle_root: Option<TapNodeHash>,
) -> ScriptBuf {
    let (output_key, _) = secp_tap_tweak(internal_key, secp, merkle_root);
    // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
    new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
}
fn secp_tap_tweak<C: Verification>(
    internal_key: UntweakedPublicKey,
    secp: &Secp256k1<C>,
    merkle_root: Option<TapNodeHash>,
) -> (XOnlyPublicKey, Parity) {
    let tweak_hash = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
    println!("secp tweak hash: {}", tweak_hash);
    let tweak = tweak_hash.to_scalar();

    let (output_key, parity) = internal_key
        .add_tweak(secp, &tweak)
        .expect("Tap tweak failed");

    (output_key, parity)
}

fn tap_tweak(internal_key: PublicKey, merkue_root: Option<TapNodeHash>) -> [u8; 32] {
    let x_only_bytes : [u8; 32]= internal_key.to_sec1_bytes()[1..].try_into().unwrap();
    let mut eng = TapTweakHash::engine();
    eng.input(&x_only_bytes);
    let tweak_hash = TapTweakHash::from_engine(eng);


    let tweak_bytes = tweak_hash.to_byte_array();

    let tweaked_point = tweak_pubkey(internal_key, &tweak_bytes);
    let compressed = tweaked_point.to_encoded_point(true);
    let x_coordinate = compressed.x().unwrap();

    let pubx: [u8; 32] = x_coordinate.as_slice().try_into().unwrap();

    pubx
}

pub fn tweak_pubkey(pubkey: PublicKey, tweak_bytes: &[u8; 32]) -> ProjectivePoint {
    let tweak_point = k256::SecretKey::from_bytes(tweak_bytes.into())
        .unwrap()
        .public_key()
        .to_projective();

    let pub_point = pubkey.to_projective();
    let pub_affine = pubkey.as_affine();
    let tweaked = if pub_affine.y_is_odd().unwrap_u8() == 1 {
        tweak_point - pub_point
    } else {
        pub_point + tweak_point
    };

    tweaked
}
