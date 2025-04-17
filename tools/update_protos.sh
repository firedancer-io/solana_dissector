#!/bin/bash

set -e

rm -f protos/*.proto

URI=https://raw.githubusercontent.com/jito-labs/mev-protos/refs/heads/master/
wget -P protos \
  $URI/auth.proto \
  $URI/block_engine.proto \
  $URI/bundle.proto \
  $URI/packet.proto \
  $URI/shared.proto
