# OutputZero

`OutputZero` is a proof of concept tool for proving Bitcoin UTXO set inclusion
in zero knowledge.

## Applications 
Since unspent transaction outputs is a scarce resource, having a way of
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

The prover starts by creating a regular Bitcoin Taproot public key `P`. This
could be any valid taproot internal key, for instance a Musig2 aggregate key.

The prover then chooses a random blinding secret `r` that will be used to blind
the key before using it:

```
beta = hash(r || P)
P_out = P + beta * G
```

The `beta` acts as a obfuscator to the key that goes onchain, making it
impossible to derive the link between `P` and `P_out` without knowledge of
`beta`.

Now the prover can send money to `P_out`, manifesting it as an output on-chain.

Proving control of the UTXO now goes as follows:
- The prover can create a signature for an arbitrary message using public key
  `P`, proving ownership.

The prover then creates a ZK-STARK proof using the [Risc0 ZKVM](https://github.com/risc0/risc0) 
that proves the following:

- The prover has a secret `r` such that 
```
beta = hash(r || P)
P_out = P + beta * G
```
- The prover has a proof showing that the public key `P_out` is found in the
  Utreexo set. The Utreexo root hash is shown to the verifier.

This ZK-proof is convincing the verifier that the prover is able to sign for 
the output in the UTXO set (if he can sign for `P` and knows `beta` then he can
also sign for `P_out`).

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
  [rpc-utreexo-bridge](https://github.com/Davidson-Souza/rpc-utreexo-bridge) 
  making sure using this revision: 
  https://github.com/halseth/rpc-utreexo-bridge/commit/4a49a589018c22da67061b5e233fe8ff45670f4a.
- Set environment variables to match the bitcoind instance: 

```
$ BITCOIN_CORE_RPC_URL="..."
$ BITCOIN_CORE_COOKIE_FILE="[..]/.cookie"
```

Start the bridge and let it index while you continue to the next step:
```
 $ bridge --network signet
```

Now create a public key and a random secret and pass it to OutputZero: 

```bash
$ cargo run -- --pubkey "027536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4" --blind-secret-hex "a3b1c5d2e7f9a8b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4" --derive
sec1 pub: 027536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4
blinded tap key : 02b123a2aa4184bacf8d7879023c6dc053aeddd64ed4ca3bc6ce3519c95e1b4c75
xonly pub: b123a2aa4184bacf8d7879023c6dc053aeddd64ed4ca3bc6ce3519c95e1b4c75
address: tb1pu3l57s32yhmegykrq6a7pe7e05ckvdwka9yvr72hlhx8dwh5kesqudhsq7
```

You can now fund the given address with some signetBTC, then wait for the
transaction to confirm and Bitcoin Core to sync to the block (feel free to use
the above keys or deposit tx for testing).

After having the coins confirmed, we will get the utreexo accumulator and
proofs from the bridge:

```
$ curl http://127.0.0.1:3000/leaf/ad62462baf935489ab6633563c1b11859f292fe355eff7eb0c90b2a0a3e3ab0e:1 | jq
{
  "data": {
    "hash": "600faadb708702e433dda62aee7aa1e712d7fa58c2886c7d0a273910724744db",
    "leaf_data": {
      "block_hash": "000000531547656158a86c79718462f348c7c2f5d7aff509905b4c0cc9fd79c1",
      "block_height": 236206,
      "hash": "600faadb708702e433dda62aee7aa1e712d7fa58c2886c7d0a273910724744db",
      "is_coinbase": false,
      "prevout": "ad62462baf935489ab6633563c1b11859f292fe355eff7eb0c90b2a0a3e3ab0e:1",
      "utxo": {
        "script_pubkey": "5120e47f4f422a25f79412c306bbe0e7d97d316635d6e948c1f957fdcc76baf4b660",
        "value": 10000
      }
    }
  },
  "error": null
}
$ curl http://127.0.0.1:3000/prove/600faadb708702e433dda62aee7aa1e712d7fa58c2886c7d0a273910724744db | jq -c '.data' > proof.json
$ curl http://127.0.0.1:3000/acc | jq -c '.data' > acc.json
$ bitcoin-cli --signet getrawtransaction ad62462baf935489ab6633563c1b11859f292fe355eff7eb0c90b2a0a3e3ab0e > tx.hex
```

Now we can run OutputZero with these proofs, in addition to some metadata about
the tx and block it confirmed in:

```bash
$ cargo run --release -- --utreexo-acc "`cat acc.json`" --utreexo-proof "`cat proof.json`" --leaf-hash '600faadb708702e433dda62aee7aa1e712d7fa58c2886c7d0a273910724744db' --receipt-file 'receipt.bin'  --tx-hex "`cat tx.hex`" --vout 1 --block-height 236206 --block-hash '000000531547656158a86c79718462f348c7c2f5d7aff509905b4c0cc9fd79c1' --proof-type 'default' --pubkey "027536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4" --blind-secret-hex "a3b1c5d2e7f9a8b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
```

This command will create a ZK proof as detailed in the Architecture section.
The `receipt.bin` file contains this proof, that can be checked by any verifier
independently.

### Verification
The proof can be verified using

```bash
cargo run --release -- --utreexo-acc "`cat acc.json`"  --receipt-file 'receipt.bin' --verify
```

Note that the accumulator needed to verify the proof is the same one needed to
create it. But since utreexo accumulators are deterministic, it can be
independently created by the verifier as long as it is communicated which block
height one is using when creating the proof.

## Benchmarks, Apple M1 Max (succint proof type)
- Proving time is about 15 seconds.
- Verification time is ~55 ms.
- Proof size is 223 kB.

## Limitations
This is a rough draft of how a tool like this could look like. It has
plenty of known limitations and should absolutely not be used with keys
controlling real (mainnet) coins.

A non-exhaustive list (some of these could be relatively easy to fix):

- Only supports taproot keyspend outputs.
- Only supports testnet3 and signet.
- Only proving existence, selectively revealing more about the output is not
  supported.
- ... and many more.

