#!/bin/bash

set -ex

# git clone https://github.com/firedancer-io/solana-packets packets

COMMON_FLAGS=(-X lua_script:solana.lua -o "uat:protobuf_search_paths:\"$(pwd)/protos\",\"TRUE\"" -V -T text)

tshark -r packets/BUNDLE/grpc_bundle_response.pcapng ${COMMON_FLAGS[*]} | unexpand -t 4 > packets/BUNDLE/grpc_bundle_response.pcapng.txt
