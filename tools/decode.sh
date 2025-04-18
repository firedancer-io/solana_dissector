#!/bin/bash

set -ex

# git clone https://github.com/firedancer-io/solana-packets packets

COMMON_FLAGS=(-X lua_script:solana.lua -V -T text)
BUNDLE_FLAGS=("${COMMON_FLAGS[@]}" -o "uat:protobuf_search_paths:\"$(pwd)/protos\",\"TRUE\"")
GOSSIP_FLAGS=("${COMMON_FLAGS[@]}" -o "uat:user_dlts:\"User 0 (DLT=147)\",\"solana.gossip\",\"0\",\"\",\"\",\"\"")
TURBINE_FLAGS=("${COMMON_FLAGS[@]}" -o "uat:user_dlts:\"User 0 (DLT=147)\",\"solana.shreds\",\"0\",\"\",\"\",\"\"")

tshark -r packets/BUNDLE/grpc_bundle_response.pcapng "${BUNDLE_FLAGS[@]}" | unexpand -t 4 > packets/BUNDLE/grpc_bundle_response.pcapng.txt

tshark -r packets/GOSSIP_PACKETS/ping.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/ping.pcap.txt

tshark -r packets/GOSSIP_PACKETS/pong.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pong.pcap.txt

tshark -r packets/GOSSIP_PACKETS/prune.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/prune.pcap.txt

tshark -r packets/GOSSIP_PACKETS/pull_request.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pull_request.pcap.txt

tshark -r packets/GOSSIP_PACKETS/pull_response.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/pull_response.pcap.txt

# takes forever
#tshark -r packets/GOSSIP_PACKETS/push.pcap "${GOSSIP_FLAGS[@]}" | awk '/Solana Gossip/,/^$/' | unexpand -t 4 > packets/GOSSIP_PACKETS/push.pcap.txt

tshark -r packets/TURBINE_PACKETS/merkle_code_resigned.pcap "${TURBINE_FLAGS[@]}" | awk '/Solana Shred/,/^$/' | unexpand -t 4 > packets/TURBINE_PACKETS/merkle_code_resigned.pcap.txt

tshark -r packets/TURBINE_PACKETS/merkle_code.pcap "${TURBINE_FLAGS[@]}" | awk '/Solana Shred/,/^$/' | unexpand -t 4 > packets/TURBINE_PACKETS/merkle_code.pcap.txt

tshark -r packets/TURBINE_PACKETS/merkle_data_resigned.pcap "${TURBINE_FLAGS[@]}" | awk '/Solana Shred/,/^$/' | unexpand -t 4 > packets/TURBINE_PACKETS/merkle_data_resigned.pcap.txt

tshark -r packets/TURBINE_PACKETS/merkle_data.pcap "${TURBINE_FLAGS[@]}" | awk '/Solana Shred/,/^$/' | unexpand -t 4 > packets/TURBINE_PACKETS/merkle_data.pcap.txt
