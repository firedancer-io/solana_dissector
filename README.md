# Wireshark dissectors for Solana

## Installation

#### macOS

Download latest version of plugin

```shell
rm -f /Applications/Wireshark.app/Contents/PlugIns/wireshark/solana.lua
curl --output /Applications/Wireshark.app/Contents/PlugIns/wireshark/solana.lua \
  --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/firedancer-io/solana_dissector/main/solana.lua
```

To activate, hit Cmd+Shift+L or restart Wireshark.

## Ports

Solana nodes allocate ports in a block starting at an arbitrary number.
To discover endpoints, nodes use the gossip protocol to send each other port mappings.

This plugin doesn't implement mappings yet and instead hardcodes ports.

- 8000: Gossip
- 8001, 8002: Shreds
- 8008, 8009: Repair

This might get fixed in the future, but for now, you have to use "Decode As" to select a protocol if the hardcoded mapping fails.

## mev-protos

Provided [mev-protos](https://github.com/jito-labs/mev-protos) are added to the Wireshark search path,
solana_dissector will decode Solana Transactions occurring in bundles received via gRPC.

## Development

- 🚧 Gossip protocol
  - Messages
    - ✅ Pull Request
    - ✅ Pull Response
    - ✅ Push Message
    - ✅ Prune Message
    - ✅ Ping Message
    - ✅ Pong Message
  - Types
    - ✅ Socket Address
    - ✅ Transaction (legacy)
    - ❌ Transaction (v0)
  - CRDS
    - ✅ Contact Info
    - ✅ Vote
      - ❌ Vote program data
    - ✅ Lowest Slot
    - ✅ Snapshot Hashes
    - ✅ Accounts Hashes
    - ✅ Epoch Slots
    - ✅ Legacy Version
    - ✅ Version
    - ✅ Node Instance
    - ❌ Duplicate Shred
    - ✅ Incremental Snapshot Hashes
- ✅ Shreds
  - ✅ Legacy Shreds
  - ✅ Merkle Shreds
  - ✅ Chained Merkle Shreds
  - ✅ Chained Resigned Merkle Shreds
  - ❌ FEC Recovery
- ✅ Repair
  - ✅ Legacy types
  - ✅ Pong
  - ✅ WindowIndex
  - ✅ HighestWindowIndex
  - ✅ Orphan
  - ✅ AncestorHashes
- ✅ TPU (UDP)
- ❌ TPU (QUIC)
- ✅ mev-protos
