# Wireshark dissectors for Solana

## Installation

#### macOS

Download latest version of plugin

```shell
rm -f /Applications/Wireshark.app/Contents/PlugIns/wireshark/solana.lua
curl --output /Applications/Wireshark.app/Contents/PlugIns/wireshark/solana.lua \
  --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/terorie/solana_dissector/main/solana.lua
```

To activate, hit Cmd+Shift+L or restart Wireshark.

## Acknowledgements

- Plugin by [@terorie (Richard Patel)](https://github.com/terorie)
- Base58 decoder by [@catwell (Pierre Chapuis)](https://github.com/catwell)
  - Taken from [plc](https://github.com/philanc/plc), MIT License

## Development

- 🚧 Gossip protocol
  - Messages
    - ❌ Pull Request
    - ✅ Pull Response
    - ❌ Push Message
    - ❌ Prune Message
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
    - ❌ Lowest Slot
    - ✅ Snapshot Hashes
    - ✅ Accounts Hashes
    - ❌ Epoch Slots
    - ❌ Legacy Version
    - ❌ Version
    - ✅ Node Instance
    - ❌ Duplicate Shred
    - ❌ Incremental Snapshot Hashes
- ❌ TVU
- ❌ Repair
- ❌ TPU
