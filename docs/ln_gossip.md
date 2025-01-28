## Privacy preserving Lightning gossip

This document describes a proposal for making Lightning channel gossip more
private, avoiding the need for revealing the channel outpoint.

It is based on Utreexo and zero-knowledge proofs, and is accompanied with a
proof-of-concept Rust implementation.

The proposal is created as an extension to the gossip v1.75 proposal for
taproot channel gossip and intended to be used as an optional feature for
privacy conscious users.

### Privacy of Lightning channel gossip
TODO

### Taproot gossip (gossip v1.75)
TODO: desribe current proposal

Example `channel_announcement_2`:
```json
{
  "ChainHash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  "ShortChannelID": "1000:100:0",
  "Capacity": 100000,
  "NodeID1": "0246175dd633eaa1c1684a9e15d218d247e421b009642f3e82e9f138ad9d645e03",
  "NodeID2": "02b651f157c5cf7bfbf07d52855c21aca861d7e3b8711d84cb04149e0a67151e16",
  "BitcoinKey1": "027fc1e3f6f5a67b804cb86d813adf94f89ea1de63f630607d4c31242d58306043",
  "BitcoinKey2": "03fef5084b98aa37757acce81d25148cfdb9592142567c6265e39b082e73c4d54",
  "MerkleRootHash": null,
  "Signature": {
    "bytes": "5c14ad15b614c9f91fd5c66b7bfe3f3552427c6d5e6d598f5838c5d219cdd0b89c72ad6a3effe5d995387563b80dfb1b59da599c936c705ad8dfd6da8288b89b",
    "sigType": 1
  },
}
```

## ZK-gossip 
What we propose is an extension to the taproot gossip proposal, that makes it
possible for the two channel parties to remove the link between the channel and
on-chain output.

In order to still be able to protect the network from channel DOS attacks, we
require the channel annoucement message to include a ZK-proof that proves the
inclusion of the channel in the UTXO set, and that it is controlled by the two
nodes in the graph.

In order to create the ZK proof with these properties, we start with the data
already contained in the regular taproot gossip channel announcment:

1) `node_id_1`, `node_id_2`
2) `bitcoin_key_1`, `bitcoin_key_2`
3) `merkle_root_hash`
4) `signature`
5) `capacity`

(we'll ignore the `merkle_root_hash` for now).

In addition we assemble a Utreexo accumulator and a proof for the channel
output's inclusion in this accumulator.

Using these pieces of data we create a ZK-proof that validates the following:

1) `bitcoin_keys = MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2)`
2) `P_agg_out = MuSig2.KeyAgg(bitcoin_keys)`
3) Check `capacity <= vout.value`
4) Check `P_agg_out = vout.script_pubkey`
3) Verify that `vout` is in the UTXO set using the utreexo accumulator and proof.
4) `P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2))`
5) Verify the signaure against `P_agg`
6) `pk_hash = hash(bitcoin_keys[0] || bitcoin_keys[1])`

We then output (or make public) the two `node_ids`, the signed data, utreexo accumulator and `pk_hash`.

Now we can output a proof (ZK-SNARK, groth16) of 256 bytes, and assemble a new
`channel_announcement_zk` (since messages are TLV, this should really be
combined with the `channel_announcement_2` with appropriate fields set):

```json
{
  "ChainHash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  "Capacity": 100000,
  "NodeID1": "0246175dd633eaa1c1684a9e15d218d247e421b009642f3e82e9f138ad9d645e03",
  "NodeID2": "02b651f157c5cf7bfbf07d52855c21aca861d7e3b8711d84cb04149e0a67151e16",
  "UtreexoRoot": "4b07311e3e774f0db3bcedee47c56fe30da326d9271d1a2558a5975ab4214478",
  "ZKType": "9bce41211c9d71e1ed07a2a5244f95ab98b0ba3a6e95dda9c87ba071ff871418",
  "ZKProof": "6508d8476086238076bb673005f9ef3bfe7f0c198a1d4f6fcee65e19478b422c512aefd004f8f476d0ef5939dc4339e3e19347a6ab60fe5714e9d3e3e77417499dbf18da68dfd942d79c8bf4cf811f615334f4643befb267a189d8e6b05509760bfd7add9aa9ecbce38db277bf11b1b94e147b504e75be5405066421aad8e10b49d105a33241742bafe611b4025ffa35d066fc87e11df595030d18b962ad5917ef1f73c97d660c1e62c7e392d51821ec342b2faf763d2a9177d13471c8b2a829578fd401d76aa8ae5642937f48573e657a5af14fda5f7a39216dda05b183121913088d2d0e0c1902d1f656b5d769b95040a40ef5a9ffd87f550545b0a5bc2505",
  "PKHash": "be7d602934c5ce95000ee989748f6c892ce16fb4276389ec15bc0764fbc4bea5"
}
```

`ZKType` is the unique identifier for the verification program, and is often a
unique hash of the binary representation of the verifier. This makes it easy to
move to a new proof type. `pk_hash` acts as a unique channel identifier.

(note: the `pk_hash` is not unique if the two nodes reuse their public keys for
a new output. Maybe this can be used to move the channel to a bigger UTXO
without closing it...)

### Creating proofs
When opening a channel, the two channel counterparties must create the ZK-proof
in order to announce the channel. In the current POC this is requires a decent
hardware setup in order to be effective (~minutes on a beefy laptop).

It should be noted that only nodes announcing public channels need to do this,
and they usually require a certain level of hardware to be effective routers
anyway.

It is also assumed that proving time will come down as advances are made in
proof systems and hardware acceleration.

### Handling received channel_announcement_zk
When a node receives a `channel_accnouncement_zk` message, it will first use
the `pk_hash` to check whether this is a channel already known to the node. The
`pk_hash` is deterministic and unique per channel. It will then verify the
proof if it has a type known to the node. Otherwise it will ignore it.

Since we can no longer detect channels closing on-chain, we must require
periodic refreshes of announcememnts, proving the channel is still in the utxo
set. We propose setting this to around two weeks. With legacy channels we
already have the problem of not knowing whether an channel unspent on-chain is
active, so some kind of liveness signal is needed regardless.

### Caveats
- Proving is slow.
    - One is not really in a hurry announcing a channel, so this is most likely not a problem as these get optimized.
- Proofs are large.
    - STARKS (using Risc0 as in the proof-of-concept) are around 200kB.
    - Wrapping them in groth16 brings this down to 200 bytes.
- Verification is slow-ish. 
    - This can likely be heavily optimized.
    - groth16 proofs are much faster to verify than STARKS.

### Wins
- This can be used today, no softforks needed :)
- Easier to be a light-node.
    - Light clients need to get a periodic refresh of their Utreexp accumulator
      (from a trusted source, or a semi-trusted source that can prove that the
      accumulator is correctly crafted).
    - With the accumulator they can validate the proofs just as a full node.

### Proof-of-concept
I've preperad a branch with accompanying code and documents walking through the
process of creating a proof from the original channel announcment: [Musig2
example](https://github.com/halseth/output-zero/blob/musig2/docs/musig2.md).

It is based on RiscZero, a versatile framework for creating proofs of execution
for RISC-V binaries. This means that is easy to add more contrainsts to the
verification of the UTXOs if useful.

