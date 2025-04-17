#!/usr/bin/env python3

__author__ = "Richard Patel"
__copyright__ = "Copyright 2025 Firedancer Contributors"
__email__ = "ripatel@jumptrading.com"
__license__ = "Apache-2.0"

import argparse
import shutil
import struct


def check_input_file(inf):
    magic_number = inf.read(4)
    if magic_number != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Input file is not a valid pcapng file")
    inf.seek(0)
    pass


def inject_keys(outf, inf, keyf):
    start = inf.tell()

    # Create a Section Header Block
    shb_hdr = struct.pack(
        "!IIIHHQHHI",
        0x0A0D0D0A,
        32,  # length prefix
        0x1A2B3C4D,
        1,  # version major
        0,  # version minor
        0,  # length placeholder
        0,
        0,  # null option
        32,  # length suffix
    )
    outf.write(shb_hdr)

    # Write Decryption Secret Blocks
    for line in keyf:
        key = line.strip().encode("utf-8")
        block_sz = 16 + ((len(key) + 3) & ~3) + 4
        dsb_hdr = struct.pack("!IIII", 0xA, block_sz, 0x544C534B, len(key))
        outf.write(dsb_hdr)
        outf.write(key)
        padding = (4 - (len(key) & 3)) & 3
        outf.write(b"\x00" * padding)
        outf.write(struct.pack("!I", block_sz))

    # Fix up section length
    section_length = outf.tell() - start
    outf.seek(start + 16)
    outf.write(struct.pack("!Q", section_length))
    outf.seek(0, 2)  # Move back to the end of the file

    # Copy all bytes from inf to outf
    inf.seek(0)
    shutil.copyfileobj(inf, outf)


def main():
    parser = argparse.ArgumentParser(description="Inject keys into pcapng file")
    parser.add_argument(
        "--keyfile", type=str, required=True, help="Path to the SSLKEYLOGFILE"
    )
    parser.add_argument(
        "--input", type=str, required=True, help="Path to original pcapng file"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output path to file with keys injected",
    )
    args = parser.parse_args()

    with open(args.keyfile, "r") as key_file:
        with open(args.input, "rb") as input_file:
            check_input_file(input_file)
            with open(args.output, "wb") as output_file:
                inject_keys(output_file, input_file, key_file)


if __name__ == "__main__":
    main()
