use std::str::{from_utf8};

use risc0_zkvm::guest::env;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha512_256};

use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use bitcoin::key::{UntweakedPublicKey};
use bitcoin::{Amount, ScriptBuf, Transaction, BlockHash, TapNodeHash, TapTweakHash, TxOut, WitnessVersion, XOnlyPublicKey};
use bitcoin::script::{Builder, PushBytes};
use bitcoin::consensus::Encodable;
use k256::schnorr;
use k256::schnorr::signature::Verifier;
use k256::elliptic_curve::sec1::ToEncodedPoint;

pub fn new_p2tr(
    internal_key: UntweakedPublicKey,
    merkle_root: Option<TapNodeHash>,
) -> ScriptBuf {
    let output_key = tap_tweak(internal_key, merkle_root);
    // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
    new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
}

fn new_witness_program_unchecked<T: AsRef<PushBytes>>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In segwit v0, the program must be 20 or 32 bytes long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}


fn tap_tweak(
    internal_key: UntweakedPublicKey,
    merkle_root: Option<TapNodeHash>,
) -> XOnlyPublicKey {
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root).to_scalar();

    let pub_bytes = internal_key.serialize();
    let pub_key : k256::PublicKey = schnorr::VerifyingKey::from_bytes(&pub_bytes).unwrap().into();
    let pub_point = pub_key.to_projective();

    let tweak_bytes = &tweak.to_be_bytes();
    let tweak_point = k256::SecretKey::from_bytes(tweak_bytes.into()).unwrap().public_key().to_projective();

    let tweaked_point = pub_point + tweak_point;
    let compressed = tweaked_point.to_encoded_point(true);
    let x_coordinate = compressed.x().unwrap();

    let ver_key = schnorr::VerifyingKey::from_bytes(&x_coordinate).unwrap();

    let pubx = XOnlyPublicKey::from_slice(ver_key.to_bytes().as_slice()).unwrap();

    pubx
}

fn main() {
    // read the input
    let msg_bytes: Vec<u8> = env::read();
    let priv_key: schnorr::SigningKey = env::read();
    let leaf_hash: NodeHash = env::read();
    let s: Stump = env::read();
    let proof: Proof = env::read();
    let sig_bytes: Vec<u8> = env::read();

    let tx: Transaction = env::read();
    let vout: u32 = env::read();
    let block_height: u32 = env::read();
    let block_hash: BlockHash = env::read();

    let lh = get_leaf_hashes(&tx, vout, block_height, block_hash);
    let lh = NodeHash::from(lh);
    assert_eq!(lh, leaf_hash);

    let internal_key = priv_key.verifying_key();

    // We'll check that the given public key corresponds to an output in the utxo set.
    let pubx = XOnlyPublicKey::from_slice(internal_key.to_bytes().as_slice()).unwrap();
    let script_pubkey = new_p2tr(pubx, None);
    let utxo = TxOut {
        value: Amount::ZERO,
        script_pubkey,
    };

    // Assert it is in the set.
    assert_eq!(s.verify(&proof, &[leaf_hash]), Ok(true));

    let mut hasher = Sha512_256::new();
    hasher.update(&priv_key.to_bytes());
    let sk_hash = hex::encode(hasher.finalize());
    let msg = from_utf8(msg_bytes.as_slice()).unwrap();

    let schnorr_sig = schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();

    internal_key
        .verify(msg_bytes.as_slice(), &schnorr_sig)
        .expect("schnorr verification failed");

    // write public output to the journal
    env::commit(&s);
    env::commit(&sk_hash);
    env::commit(&msg);
}

pub const UTREEXO_TAG_V1: [u8; 64] = [
    0x5b, 0x83, 0x2d, 0xb8, 0xca, 0x26, 0xc2, 0x5b, 0xe1, 0xc5, 0x42, 0xd6, 0xcc, 0xed, 0xdd, 0xa8,
    0xc1, 0x45, 0x61, 0x5c, 0xff, 0x5c, 0x35, 0x72, 0x7f, 0xb3, 0x46, 0x26, 0x10, 0x80, 0x7e, 0x20,
    0xae, 0x53, 0x4d, 0xc3, 0xf6, 0x42, 0x99, 0x19, 0x99, 0x31, 0x77, 0x2e, 0x03, 0x78, 0x7d, 0x18,
    0x15, 0x6e, 0xb3, 0x15, 0x1e, 0x0e, 0xd1, 0xb3, 0x09, 0x8b, 0xdc, 0x84, 0x45, 0x86, 0x18, 0x85,
];

fn get_leaf_hashes(
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
    let txid = transaction.txid();

    let leaf_hash = Sha512_256::new()
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(UTREEXO_TAG_V1)
        .chain_update(block_hash)
        .chain_update(transaction.txid())
        .chain_update(vout.to_le_bytes())
        .chain_update(header_code.to_le_bytes())
        .chain_update(ser_utxo)
        .finalize();
    sha256::Hash::from_slice(leaf_hash.as_slice())
        .expect("parent_hash: Engines shouldn't be Err")
}
