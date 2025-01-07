use std::fs::File;
// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{METHOD_ELF, METHOD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash as BitcoinHash;

use clap::Parser;

use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::stump::Stump;
use std::str::FromStr;
use std::time::SystemTime;

use bitcoin::consensus::{deserialize};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{rand, Message, Secp256k1, SecretKey, Signing};
use bitcoin::{Address, BlockHash, Network, ScriptBuf, Transaction};
use k256::schnorr;
use k256::schnorr::signature::Verifier;
use rustreexo::accumulator::proof::Proof;
use serde::{Deserialize, Serialize};

use shared::get_leaf_hashes;

fn gen_keypair<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk = SecretKey::new(&mut rand::thread_rng());
    Keypair::from_secret_key(secp, &sk)
}

/// utxozkp
#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    prove: bool,

    #[arg(long)]
    proof_type: Option<String>,

    /// File containing a receipt to verify or file to write receipt to.
    #[arg(short, long)]
    receipt_file: Option<String>,

    #[arg(long)]
    utreexo_proof: Option<String>,

    #[arg(long)]
    utreexo_acc: Option<String>,

    #[arg(long)]
    leaf_hash: Option<String>,

    #[arg(long)]
    tx_hex: Option<String>,

    #[arg(long)]
    block_height: Option<u32>,

    #[arg(long)]
    block_hash: Option<String>,

    #[arg(long)]
    vout: Option<u32>,

    /// Message to sign.
    #[arg(short, long)]
    msg: Option<String>,

    /// Sign the message using the given private key. Pass "new" to generate one at random. Leave
    /// this blank if verifying a receipt.
    #[arg(long)]
    priv_key: Option<String>,

    /// Network to use.
    #[arg(long, default_value_t = Network::Testnet)]
    network: Network,
}

#[derive(Deserialize, Serialize)]
struct CliProof {
    pub targets: Vec<u64>,
    pub hashes: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct CliStump {
    pub roots: Vec<String>,
    pub leaves: u64,
}

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let secp = Secp256k1::new();
    let network = args.network;

    // Generate a new keypair or use the given private key.
    let keypair = match args.priv_key.as_deref() {
        Some(priv_str) => {
            let keypair = if priv_str == "new" {
                gen_keypair(&secp)
            } else {
                let sk = SecretKey::from_str(&priv_str).unwrap();
                Keypair::from_secret_key(&secp, &sk)
            };

            let (internal_key, _parity) = keypair.x_only_public_key();
            let script_buf = ScriptBuf::new_p2tr(&secp, internal_key, None);
            let addr = Address::from_script(script_buf.as_script(), network).unwrap();
            println!("priv: {}", hex::encode(keypair.secret_key().secret_bytes()));
            println!("pub: {}", internal_key);
            println!("address: {}", addr);

            if priv_str == "new" {
                return;
            }

            Some(keypair)
        }
        _ => {
            if args.prove {
                println!("priv key needed");
                return;
            }
            None
        }
    };

    let receipt_file = if args.prove {
        let r = File::create(args.receipt_file.unwrap()).unwrap();
        r
    } else {
        let r = File::open(args.receipt_file.unwrap()).unwrap();
        r
    };

    let acc: CliStump = serde_json::from_str(&args.utreexo_acc.unwrap()).unwrap();
    let acc = Stump {
        leaves: acc.leaves,
        roots: acc
            .roots
            .into_iter()
            .map(|root| NodeHash::from_str(&root).expect("invalid hash"))
            .collect(),
    };

    let start_time = SystemTime::now();

    // If not proving, simply verify the passed receipt using the loaded utxo set.
    if !args.prove {
        let receipt: Receipt = bincode::deserialize_from(receipt_file).unwrap();
        verify_receipt(&receipt, &acc);
        println!("receipt verified in {:?}", start_time.elapsed().unwrap());
        return;
    }

    let proof_type: ProverOpts = match args.proof_type.as_deref() {
        None => {
            println!("using default proof type");
            ProverOpts::default()
        }
        Some("default") => {
            println!("using default proof type");
            ProverOpts::default()
        }
        Some("fast") => {
            println!("using fast proof type");
            ProverOpts::fast()
        }
        Some("succint") => {
            println!("using succint proof type");
            ProverOpts::succinct()
        }
        Some("groth16") => {
            println!("using groth16 proof type");
            ProverOpts::groth16()
        }
        Some("composite") => {
            println!("using composite proof type");
            ProverOpts::composite()
        }
        _ => {
            println!("proof type invalid");
            return;
        }
    };

    let msg_to_sign = args.msg.unwrap();
    let msg_bytes = msg_to_sign.as_bytes();
    let digest = sha256::Hash::hash(msg_bytes);
    let digest_bytes = digest.to_byte_array();
    let msg = Message::from_digest(digest_bytes);

    let proof: CliProof = serde_json::from_str(&args.utreexo_proof.unwrap()).unwrap();
    let proof = Proof {
        targets: proof.targets,
        hashes: proof
            .hashes
            .into_iter()
            .map(|root| NodeHash::from_str(&root).expect("invalid hash"))
            .collect(),
    };

    let leaf_hash = NodeHash::from_str(&args.leaf_hash.unwrap()).unwrap();

    let tx_bytes = hex::decode(&args.tx_hex.unwrap()).unwrap();
    let tx: Transaction = deserialize(&tx_bytes).unwrap();

    let vout = args.vout.unwrap();
    let block_height = args.block_height.unwrap();
    let block_hash: BlockHash = BlockHash::from_str(&args.block_hash.unwrap()).unwrap();

    let lh = get_leaf_hashes(&tx, vout, block_height, block_hash);
    println!("lh: {:?}", lh);

    let lh = NodeHash::from(lh);

    assert_eq!(lh, leaf_hash);

    // We will prove inclusion in the UTXO set of the key we control.
    let (internal_key, _parity) = keypair.unwrap().x_only_public_key();
    let priv_bytes = keypair.unwrap().secret_key().secret_bytes();
    let priv_key = schnorr::SigningKey::from_bytes(&priv_bytes).unwrap();
    let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);

    assert_eq!(tx.output[vout as usize].script_pubkey, script_pubkey);

    println!("proving {}", leaf_hash);
    println!("proof: {:?}", proof);
    assert_eq!(acc.verify(&proof, &[leaf_hash]), Ok(true));
    println!("stump proof verified");

    // Sign using the tweaked key.
    let sig = secp.sign_schnorr(&msg, &keypair.unwrap());

    // Verify signature.
    let (pubkey, _) = keypair.unwrap().x_only_public_key();
    println!("pubkey: {}", pubkey);

    let sig_bytes = sig.serialize();
    println!("secp signature: {}", hex::encode(sig_bytes));
    secp.verify_schnorr(&sig, &msg, &pubkey)
        .expect("secp verification failed");

    let pub_bytes = pubkey.serialize();

    println!("creating verifying key");
    let verifying_key = schnorr::VerifyingKey::from_bytes(&pub_bytes).unwrap();
    println!(
        "created verifying key: {}",
        hex::encode(verifying_key.to_bytes())
    );

    let schnorr_sig = schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();
    println!("schnorr signature: {}", hex::encode(schnorr_sig.to_bytes()));

    verifying_key
        .verify(msg_bytes, &schnorr_sig)
        .expect("schnorr verification failed");

    let start_time = SystemTime::now();
    let env = ExecutorEnv::builder()
        .write(&msg_bytes)
        .unwrap()
        .write(&priv_key)
        .unwrap()
        .write(&acc)
        .unwrap()
        .write(&proof)
        .unwrap()
        .write(&sig_bytes.as_slice())
        .unwrap()
        .write(&tx)
        .unwrap()
        .write(&vout)
        .unwrap()
        .write(&block_height)
        .unwrap()
        .write(&block_hash)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove_with_opts(env, METHOD_ELF, &proof_type).unwrap();
    println!("Proving took {:?}", start_time.elapsed().unwrap());

    // extract the receipt.
    let receipt = prove_info.receipt;

    verify_receipt(&receipt, &acc);

    let receipt_bytes = bincode::serialize(&receipt).unwrap();
    println!("receipt ({})", receipt_bytes.len(),);

    bincode::serialize_into(receipt_file, &receipt).unwrap();
}

fn verify_receipt(receipt: &Receipt, s: &Stump) {
    let (receipt_stump, sk_hash, msg): (Stump, String, String) = receipt.journal.decode().unwrap();

    assert_eq!(&receipt_stump, s, "stumps not equal");

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt.verify(METHOD_ID).unwrap();
    println!("priv key hash: {}", sk_hash);
    println!("signed msg: {}", msg);
}
