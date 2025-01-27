## Musig2 example

As outlined in the [Private Lightning Gossip](./ln_gossip.md) doc, a potential
use case of OutputZero is to make LN gossip more private. In order for this to
be realized, verification of Musig2 key aggregation in the ZK environment is
performed.

In this example we'll show how this is done.

### Create private keys and sign
The Musig2 key used in Taproot Lightning gossip is aggergated from 4 individual public keys. We start by creating 4 keypairs and specifying a message to sign.

```bash
$ cargo run --release --  --node-key-1-priv "new" --node-key-2-priv "new" --bitcoin-key-1-priv "new" --bitcoin-key-2-priv "new" --msg-hex "`echo "this message" | xxd -p`" --network "signet"
node_key_1:
priv: 121f7492040ebd1a484b433ba661258963d7d36cfaeab7084e520ecba4e4c1b4
pubkey: 02081f8dbfea223289d2a160cf321bea267390550c3f32c372a655f2f907cea504
xonly pub: 081f8dbfea223289d2a160cf321bea267390550c3f32c372a655f2f907cea504
address: tb1ppqym9scg7p66pscvjlelcmx445vsh9lq9v3mv93232hqvd7dppesp3mr34
node_key_2:
priv: 09951546ca93633974dc37dfc0fa3fba4fc882189a0c047eead735927aeb6ef5
pubkey: 03b73eef25490c7f00afa268cac13ae55005c60bdf322dd0a1c54e5cd06da0ef7e
xonly pub: b73eef25490c7f00afa268cac13ae55005c60bdf322dd0a1c54e5cd06da0ef7e
address: tb1pkvt6fv629lcjptgfglftjxmnwpzs6c4detk2sa437wn5smuj54psx5nfyn
bitcoin_key_1:
priv: a7862a16105e330c3d31a584df5f41c5a43e457d2d1fdb73cee76f92754ae863
pubkey: 027536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4
xonly pub: 7536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4
address: tb1prglt49pm50dtfj8wj3l7tqc94m8ytw4xm7x5jkn7famjx83nydpqkl08w7
bitcoin_key_2:
priv: e40871a76761ae4554e2c2c07e2bc80e6e0dc6c1b25792e1851cf7deb369573d
pubkey: 03a048f128b57e5750f7dcb177d7f4280cf529301801cb3f028eb9746b9228f731
xonly pub: a048f128b57e5750f7dcb177d7f4280cf529301801cb3f028eb9746b9228f731
address: tb1pjrshj2h0yyds3c279xlz9e9uelvc7hzfdagamzrknp79xz0yr7ns7sj0wz
...
tap key : 0236827c6ebdd86cf2172a2caac10ef08ca3d7643021ccf16c8eca11b393ace4e8
pub: 36827c6ebdd86cf2172a2caac10ef08ca3d7643021ccf16c8eca11b393ace4e8
address: tb1px5m3w7t2v4nk8pxeaacgc3nn8vulqakfe2uzkavpy0q24ct3n36qghem5d
signing
...
aggregate key : 0205948efcf1da93342484e6df5000b9314765ac3566476ba3549cf4ecfa54fbf8
musig sig: e9b9814e617421ca7d8c3c11979f5373fb6749d59f542edb5381be56682cd62f048988a148354c8e3cfabaf5126497d7ddff1c4e62efe5003629f358f9e47c75
musig successfully verified
```

### Funding the output
Now that we have created the keys, we also have the possibility to send money
to them. So we'll go ahead and send some signet coins to the address of the
aggregate tap key (`agg[bitcoin_key1, bitcoin_key2]`):
`tb1px5m3w7t2v4nk8pxeaacgc3nn8vulqakfe2uzkavpy0q24ct3n36qghem5d`.

In my case this resulted in the following transaction: [2a1550a17ec661037145443d3e6bbeb378ff0ee446ecd6ca85d866020c1435b6](https://mempool.space/signet/tx/2a1550a17ec661037145443d3e6bbeb378ff0ee446ecd6ca85d866020c1435b6).

After this confirms we have an on-chain output we want to sign for _without
revealing which one it is._

### Getting the Utreexo proof
Make sure you have a running bitcoind on signet, and a [utreexo bridge
node](https://github.com/Davidson-Souza/rpc-utreexo-bridge) connected to it.

We start by finding the _leaf hash_ for the output we just created.

```bash
$ curl http://127.0.0.1:3000/leaf/2a1550a17ec661037145443d3e6bbeb378ff0ee446ecd6ca85d866020c1435b6:1 | jq
{
  "data": {
    "hash": "31e66cb9812a9a66706696b226c175b7abbde6dfb98eae3e777162b7a1be731d",
    "leaf_data": {
      "block_hash": "000000038ea165485e344192ec434db1a90624dbc78bab14b6fe452645748923",
      "block_height": 232415,
      "hash": "31e66cb9812a9a66706696b226c175b7abbde6dfb98eae3e777162b7a1be731d",
      "is_coinbase": false,
      "prevout": "2a1550a17ec661037145443d3e6bbeb378ff0ee446ecd6ca85d866020c1435b6:1",
      "utxo": {
        "script_pubkey": "5120353717796a65676384d9ef708c46733b39f076c9cab82b758123c0aae1719c74",
        "value": 553396
      }
    }
  },
  "error": null
}
```

We'll get the utreexo accumulator and the proof for the inclusion of this leaf
hash into the accumulator (we'll store these to file):

```bash
$ curl http://127.0.0.1:3000/prove/31e66cb9812a9a66706696b226c175b7abbde6dfb98eae3e777162b7a1be731d | jq -c '.data' > proof_utreexo.json
$ curl http://127.0.0.1:3000/acc | jq -c '.data' > acc_utreexo.json
$ bitcoin-cli --signet getrawtransaction 2a1550a17ec661037145443d3e6bbeb378ff0ee446ecd6ca85d866020c1435b6 > tx.hex
```

### Generate the proof
Now we have all pieces ready to generate the full proof:

```bash
$ cargo run --release -- --utreexo-acc "`cat acc_utreexo.json`" --utreexo-proof "`cat proof_utreexo.json`" --leaf-hash '31e66cb9812a9a66706696b226c175b7abbde6dfb98eae3e777162b7a1be731d' --prove --receipt-file 'receipt.bin'  --msg-hex "`echo "this message" | xxd -p`" --tx-hex "`cat tx.hex`" --vout 1 --block-height 232415 --block-hash '000000038ea165485e344192ec434db1a90624dbc78bab14b6fe452645748923' --node-key-1 "02081f8dbfea223289d2a160cf321bea267390550c3f32c372a655f2f907cea504" --node-key-2 "03b73eef25490c7f00afa268cac13ae55005c60bdf322dd0a1c54e5cd06da0ef7e" --bitcoin-key-1 "027536f0c851f239cca5d97f5c6af058fd07b7c688480b3619d764ef3ca89a63e4" --bitcoin-key-2 "03a048f128b57e5750f7dcb177d7f4280cf529301801cb3f028eb9746b9228f731" --proof-type 'default' --musig-sig 'e9b9814e617421ca7d8c3c11979f5373fb6749d59f542edb5381be56682cd62f048988a148354c8e3cfabaf5126497d7ddff1c4e62efe5003629f358f9e47c75'
...
Proving took 84.877619s
committed node_key1 : 02081f8dbfea223289d2a160cf321bea267390550c3f32c372a655f2f907cea504
committed node_key2 : 03b73eef25490c7f00afa268cac13ae55005c60bdf322dd0a1c54e5cd06da0ef7e
bitcoin keys hash: ec938aa2258d7369dada32facf0e8c10c67db48fc6c15a7bb2bbf931900e9d3e
signed msg: 74686973206d6573736167650a
stump hash: e48b939f7fe439c15cc0665d926f6d5f66a0355d60b1518ba7f2c0f79b233a15
verified METHOD_ID=9bce41211c9d71e1ed07a2a5244f95ab98b0ba3a6e95dda9c87ba071ff871418
receipt (2228856). seal size: 2225440.
```

### Proof types
Risc0 has support for a few different proof types. The deafault is a composite
proof, which can be reduced in size by using the compressed succint proof type.
These are both variants of ZK-STARKS. 

One can also specify the `groth16` proof type (currently only available on x86
hardware), which will wrap the STARK proof in a ZK-SNARK and dramastically
reduce the proof size! We are talking a proof size of 256 bytes. More details
on the various proof types here: [Risc0 Proof System
Overview](https://dev.risczero.com/proof-system/).

### Verification
We can verify the proof by ommitting the `--prove` flag:

```bash
$ cargo run --release -- --receipt-file 'receipt.bin'
...
committed node_key1 : 02081f8dbfea223289d2a160cf321bea267390550c3f32c372a655f2f907cea504
committed node_key2 : 03b73eef25490c7f00afa268cac13ae55005c60bdf322dd0a1c54e5cd06da0ef7e
bitcoin keys hash: ec938aa2258d7369dada32facf0e8c10c67db48fc6c15a7bb2bbf931900e9d3e
signed msg: 74686973206d6573736167650a
stump hash: e48b939f7fe439c15cc0665d926f6d5f66a0355d60b1518ba7f2c0f79b233a15
verified METHOD_ID=9bce41211c9d71e1ed07a2a5244f95ab98b0ba3a6e95dda9c87ba071ff871418
receipt verified in 411.941ms
```
