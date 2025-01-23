use std::str::{from_utf8};

use risc0_zkvm::guest::env;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha512_256};

use bitcoin::key::{UntweakedPublicKey};
use bitcoin::{ScriptBuf, Transaction, BlockHash, TapNodeHash, TapTweakHash, WitnessVersion, XOnlyPublicKey};
use bitcoin::script::{Builder, PushBytes};
use k256::schnorr;
use k256::schnorr::signature::Verifier;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

use shared::{get_leaf_hashes, verify_musig, aggregate_keys, sort_pubkeys};

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
    //TODO: take in nodeid1, nodeid2, bitcoinkey1, bitcoinkey2 need tweak?
    // check combining bitcoin keys give a key that is in the UTXO set.
    // combine all 4 keys and check that the signature is valid for the aggregate key
    // How to avoid proof reuse? cannot do hash of priv key easily, since there are two nodes maybe
    // do hash of the individual public keys? since they won't ever go onchain


    // read the input
    let msg_bytes: Vec<u8> = env::read();
    let s: Stump = env::read();
    let proof: Proof = env::read();

    let tx: Transaction = env::read();
    let vout: u32 = env::read();
    let block_height: u32 = env::read();
    let block_hash: BlockHash = env::read();
    let all_pubs: Vec<PublicKey> = env::read();
    let musig_sig_bytes: Vec<u8> = env::read();

    let mut musig_pubs = all_pubs.clone();
    sort_pubkeys(&mut musig_pubs);

    assert_eq!(
        verify_musig(musig_pubs.clone(), musig_sig_bytes.clone().try_into().unwrap(), &msg_bytes),
        true,
    );

    // Aggregate the bitcoin keys.
    let bitcoin_key1 = all_pubs[2];
    let bitcoin_key2 = all_pubs[3];
    let mut bitcoin_keys =vec![bitcoin_key1, bitcoin_key2];
    sort_pubkeys(&mut bitcoin_keys);
    let tap_pub = aggregate_keys(bitcoin_keys);

    let pub_bytes : [u8; 32]= tap_pub.to_sec1_bytes()[1..].try_into().unwrap();
    let pubx = XOnlyPublicKey::from_slice(&pub_bytes).unwrap();

    let lh = get_leaf_hashes(&tx, vout, block_height, block_hash);
    let leaf_hash = NodeHash::from(lh);

    // We'll check that the given public key corresponds to an output in the utxo set.
    let script_pubkey = new_p2tr(pubx, None);

    // assert internal key is in tx used to calc leaf hash
    assert_eq!(tx.output[vout as usize].script_pubkey, script_pubkey);

    // Assert it is in the set.
    assert_eq!(s.verify(&proof, &[leaf_hash]), Ok(true));

    let mut hasher = Sha512_256::new();
    hasher.update(&bitcoin_key1.to_sec1_bytes());
    hasher.update(&bitcoin_key2.to_sec1_bytes());
    let pk_hash = hex::encode(hasher.finalize());

    let mut shasher = Sha512_256::new();
    s.serialize(&mut shasher).unwrap();
    let stump_hash = hex::encode(shasher.finalize());

    // write public output to the journal
    env::commit(&stump_hash);
    env::commit(&pk_hash);
    env::commit(&msg_bytes);
}