#!/bin/bash

set -ex

# git clone https://github.com/firedancer-io/solana-packets packets

COMMON_FLAGS=(-X lua_script:solana.lua -V -T text)
BUNDLE_FLAGS=("${COMMON_FLAGS[@]}" -o "uat:protobuf_search_paths:\"$(pwd)/protos\",\"TRUE\"")
GOSSIP_FLAGS=("${COMMON_FLAGS[@]}" -o "uat:user_dlts:\"User 0 (DLT=147)\",\"solana.gossip\",\"0\",\"\",\"\",\"\"")

tshark -r packets/BUNDLE/grpc_bundle_response.pcapng "${BUNDLE_FLAGS[@]}" | unexpand -t 4 > packets/BUNDLE/grpc_bundle_response.pcapng.txt

tshark -r packets/GOSSIP_PACKETS/ping.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/ping.txt

tshark -r packets/GOSSIP_PACKETS/pong.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pong.txt

tshark -r packets/GOSSIP_PACKETS/prune.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/prune.txt

tshark -r packets/GOSSIP_PACKETS/pull_request.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pull_request.txt

tshark -r packets/GOSSIP_PACKETS/pull_response.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pull_response.txt

tshark -r packets/GOSSIP_PACKETS/push.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/push.txt
