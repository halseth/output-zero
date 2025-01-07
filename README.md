# OutputZero
`OutputZero` is a proof of concept tool for proving Bitcoin UTXO set inclusion in
zero knowledge.

## Applications 
Since unspent transaction outputs is a scare resource, having a way of
cryptographically prove you own one without revealing anything about the output
is useful for all sorts of anti-DOS applications.

Examples are:
- Lightning channel announcements: prove the channel exist without revealing
  it.
- Proof-of-reserves: prove you control a certain amount of coins without
  revealing which ones.
- etc

## Architecture 
The tool works with accumulators and proofs from a
[Utreexo](https://dci.mit.edu/utreexo) client. In the examples we will be using
the [rpc-utreexo-bridge](https://github.com/Davidson-Souza/rpc-utreexo-bridge),
which acts as a utreexo bridge to Bitcoin Core.

After being given the utreexo accumulator and proof, the prover signs a message
using the private key for the output with public key `P`, proving that he
controls the coins. 

The prover then creates a ZK-STARK proof using the [Risc0 ZKVM](https://github.com/risc0/risc0) 
that proves the following:

- The prover has a valid signature for an arbitrary message for a public key
  `P`, where `P = x * G`. The message and `hash(x)`is shown to the verifier.
- The prover has a proof showing that the public key P is found in the Utreexo
  set. The Utreexo root is shown to the verifier.

This ZK-proof is convincing the verifier that the prover has the private key to
the output in the UTXO set.

## Quick start

### Requirements 
Install the `risc0` toolchain: https://github.com/risc0/risc0?tab=readme-ov-file#getting-started

### Proof creation
Set ut a Bitcoin Core node running on signet, and remember to activate txindex:
```
$ bitcoind --signet --txindex
```

Now we set ut a utreexo bridge that will index the chain and create the inclusion proofs we need:
- Install the bridge according to
  [rpc-utreexo-bridge](https://github.com/Davidson-Souza/rpc-utreexo-bridge).
- Set environment variables to match the bitcoind instance: 

```
$ BITCOIN_CORE_RPC_URL="..."
$ BITCOIN_CORE_COOKIE_FILE="[..]/.cookie"
```

Start the bridge and let it index while you continue to the next step:
```
 $ bridge --network signet
```

Now we can create an address using OutputZero, and send som signet coins to it:

```bash
$ cargo run --release -- --priv-key "new"
priv: 6fc5d9e0dcd0cad79cea037a28850abe4a661d7a2c2de72311feea912acc5dbf
pub: bd70caa34056cc4bb2b66f44e038c52f1f87f4fb20703f6209617bb58a032a5d
address: tb1pnpvxrjhlwzn7rfggv2tvx508tuvha38ez3x993r865cxcn3xrexqn9t6jl
```

You can now fund the given address with some signetBTC, then wait for the
transaction to confirm and Bitcoin Core to sync to the block (feel free to use
the above private key or deposit tx for testing, but please don't spend the coins).

After having the coins confirmed, we will get the utreexo accumulator and
proofs from the bridge (TODO: show how to get leaf hash):

```
$ curl http://127.0.0.1:3000/prove/3baea3c5fbc3afb0ec11379416a68a1e2a64df318ea611f58213e87c50d8ccd1 | jq -c '.data' > proof.json
$ curl http://127.0.0.1:3000/acc | jq -c '.data' > acc.json
$ bitcoin-cli --signet getrawtransaction 48356de0a84cd6022ff84a70f805922ec7c799c1a01d683b8c906d38824e71e2 > tx.hex
```

Now we can run OutputZero with these proofs, in addition to some metadata about the tx and block it confirmed in:

```bash
$ cargo run --release -- --utreexo-acc "`cat acc.json`" --utreexo-proof "`cat proof.json`" --leaf-hash '3baea3c5fbc3afb0ec11379416a68a1e2a64df318ea611f58213e87c50d8ccd1' --prove --priv-key '6fc5d9e0dcd0cad79cea037a28850abe4a661d7a2c2de72311feea912acc5dbf' --receipt-file 'receipt.bin'  --msg 'this is message' --tx-hex "`cat tx.hex`" --vout 1 --block-height 226735 --block-hash '00000019cfb5ef098766c4602dbfbb7351ad61a71c2f451d80feb2eb65563b63'
```

This command will create a ZK proof as detailed in the Architecture section.
The `receipt.bin` file contains this proof, that can be checked by any verifier
independently.

### Verification
The proof can be verified using

```bash
cargo run --release -- --utreexo-acc "`cat acc.json`"  --receipt-file 'receipt.bin'  --msg 'this is message'
```

Note that the the accumulator needed to verify the proof is the same one needed
to create it. But since utreexo accumulators are deterministic, it can be
independently created by the verifier as long as it is communicated which block
height one is using when creating the proof.

## Benchmarks, Apple M1 Max
- Proving time is about 48 seconds.
- Verification time is ~254 ms.
- Proof size is 1.4 MB.

## Limitations
This is a rough first draft of how a tool like this could look like. It has
plenty of known limitations and should absolutely not be used with private keys
controlling real (mainnet) coins.

A non-exhaustive list (some of these could be relatively easy to fix):

- Only supports taproot keyspend outputs.
- Only supports testnet3 and signet.
- Only proving existence, selectively revealing more about the output is not
  supported.
- Proving time is not optimized.
- Proof size is not attempted optimized.
- Private key must be hot.
- ... and many more.

